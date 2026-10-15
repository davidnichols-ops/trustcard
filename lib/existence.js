// Layer 1 — Existence verification
//
// Given a registry entry, verifies that the declared artifacts actually exist:
//   - GitHub repository URL resolves
//   - npm package name resolves
//   - Publisher identity (reverse-DNS namespace → GitHub owner)
//
// Uses public APIs (no auth required for basic checks, but GitHub has rate
// limits for unauthenticated requests — 60/hour per IP). For population-scale
// runs, set GITHUB_TOKEN env var for 5000/hour.
//
// Output format matches the North Star's Layer 1 model:
//   { identity: { repository_verified, package_verified, publisher_verified } }

/**
 * Verify a GitHub repository URL exists.
 * Uses the GitHub REST API (GET /repos/{owner}/{repo}).
 * @param {string} repoUrl - full GitHub URL (e.g. https://github.com/owner/repo)
 * @returns {Promise<{verified: boolean, exists: boolean, details: object, error: string|null}>}
 */
export async function verifyGitHubRepo(repoUrl) {
  if (!repoUrl) return { verified: false, exists: false, details: {}, error: "no repository URL" };

  // Parse owner/repo from URL
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/i);
  if (!match) return { verified: false, exists: false, details: {}, error: "not a GitHub URL" };

  const [, owner, repo] = match;
  const repoClean = repo.replace(/\.git$/, "").replace(/\/$/, "");

  const headers = { Accept: "application/vnd.github+json" };
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_FACTORY_TOKEN || process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    const resp = await fetch(`https://api.github.com/repos/${owner}/${repoClean}`, { headers });

    if (resp.status === 200) {
      const data = await resp.json();
      return {
        verified: true,
        exists: true,
        details: {
          owner: data.owner?.login,
          ownerId: data.owner?.id,
          ownerType: data.owner?.type,
          repoId: data.id,
          fullName: data.full_name,
          private: data.private,
          archived: data.archived,
          stars: data.stargazers_count,
          forks: data.forks_count,
          pushedAt: data.pushed_at,
          createdAt: data.created_at,
          updatedAt: data.updated_at,
          language: data.language,
          license: data.license?.spdx_id,
          openIssues: data.open_issues_count,
          defaultBranch: data.default_branch,
          description: data.description,
        },
        error: null,
      };
    }

    if (resp.status === 404) {
      return { verified: true, exists: false, details: {}, error: null };
    }

    if (resp.status === 403) {
      // Rate limited
      const remaining = resp.headers.get("x-ratelimit-remaining");
      const reset = resp.headers.get("x-ratelimit-reset");
      return {
        verified: false,
        exists: false,
        details: {},
        error: `rate limited (remaining: ${remaining}, resets at: ${reset})`,
      };
    }

    return { verified: false, exists: false, details: {}, error: `HTTP ${resp.status}` };
  } catch (e) {
    return { verified: false, exists: false, details: {}, error: e.message };
  }
}

/**
 * Verify an npm package exists in the npm registry.
 * @param {string} pkgName - npm package name (without version)
 * @returns {Promise<{verified: boolean, exists: boolean, details: object, error: string|null}>}
 */
export async function verifyNpmPackage(pkgName) {
  if (!pkgName) return { verified: false, exists: false, details: {}, error: "no package name" };

  // Strip version if present
  const name = pkgName.split("@")[0] || pkgName;
  if (!name || name === "@") return { verified: false, exists: false, details: {}, error: "invalid package name" };

  try {
    const resp = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`, {
      headers: { Accept: "application/json" },
    });

    if (resp.status === 200) {
      const data = await resp.json();
      const latestVersion = data["dist-tags"]?.latest;
      const versionCount = Object.keys(data.versions || {}).length;
      const latestData = data.versions?.[latestVersion] || {};
      return {
        verified: true,
        exists: true,
        details: {
          name: data.name,
          latestVersion,
          versionCount,
          description: data.description,
          license: latestData.license,
          repository: latestData.repository?.url,
          homepage: latestData.homepage,
          maintainerCount: (data.maintainers || []).length,
          created: data.time?.created,
          modified: data.time?.modified,
        },
        error: null,
      };
    }

    if (resp.status === 404) {
      return { verified: true, exists: false, details: {}, error: null };
    }

    return { verified: false, exists: false, details: {}, error: `HTTP ${resp.status}` };
  } catch (e) {
    return { verified: false, exists: false, details: {}, error: e.message };
  }
}

/**
 * Verify publisher identity from the server's reverse-DNS name.
 * For io.github.* names, the publisher should be a GitHub user/org.
 * @param {string} serverName - MCP server name (e.g. io.github.owner/server)
 * @param {object} repoDetails - optional, from verifyGitHubRepo
 * @returns {Promise<{verified: boolean, publisher: string, source: string, error: string|null}>}
 */
export async function verifyPublisher(serverName, repoDetails = {}) {
  if (!serverName) return { verified: false, publisher: null, source: "none", error: "no server name" };

  // Parse reverse-DNS name
  // io.github.owner/server → owner is the GitHub user/org
  // me.adamjones/server → adamjones.me domain owner
  const githubMatch = serverName.match(/^io\.github\.([^/]+)\//i);
  if (githubMatch) {
    const claimedOwner = githubMatch[1];
    const repoOwner = repoDetails?.details?.owner;

    if (repoOwner && repoOwner.toLowerCase() === claimedOwner.toLowerCase()) {
      return {
        verified: true,
        publisher: claimedOwner,
        source: "github-repo-match",
        error: null,
      };
    }

    if (repoOwner && repoOwner.toLowerCase() !== claimedOwner.toLowerCase()) {
      return {
        verified: false,
        publisher: claimedOwner,
        source: "github-mismatch",
        error: `registry claims owner "${claimedOwner}" but repo owner is "${repoOwner}"`,
      };
    }

    // No repo details — try to verify the GitHub user exists
    try {
      const headers = { Accept: "application/vnd.github+json" };
      const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_FACTORY_TOKEN || process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
      if (token) headers.Authorization = `Bearer ${token}`;

      const resp = await fetch(`https://api.github.com/users/${claimedOwner}`, { headers });
      if (resp.status === 200) {
        const data = await resp.json();
        return {
          verified: true,
          publisher: claimedOwner,
          source: "github-user-exists",
          error: null,
          details: { type: data.type, id: data.id, publicRepos: data.public_repos },
        };
      }
      if (resp.status === 404) {
        return { verified: false, publisher: claimedOwner, source: "github-user-not-found", error: null };
      }
      return { verified: false, publisher: claimedOwner, source: "github-api-error", error: `HTTP ${resp.status}` };
    } catch (e) {
      return { verified: false, publisher: claimedOwner, source: "github-api-error", error: e.message };
    }
  }

  // Non-github namespace — can't verify without DNS/domain check
  return {
    verified: false,
    publisher: serverName.split("/")[0],
    source: "unknown-namespace",
    error: "no verification method for this namespace",
  };
}

/**
 * Run full Layer 1 existence verification on a registry entry.
 * @param {object} entry - a server entry from the registry crawler
 * @returns {Promise<object>} Layer 1 result
 */
export async function verifyExistence(entry) {
  const result = {
    serverName: entry.name,
    version: entry.version,
    identity: {
      repository_verified: false,
      package_verified: false,
      publisher_verified: false,
    },
    repository: null,
    package: null,
    publisher: null,
    errors: [],
    verifiedAt: new Date().toISOString(),
  };

  // 1. Repository existence
  if (entry.repoUrl) {
    const repoResult = await verifyGitHubRepo(entry.repoUrl);
    result.repository = repoResult;
    result.identity.repository_verified = repoResult.exists;
    if (repoResult.error) result.errors.push(`repo: ${repoResult.error}`);

    // 3. Publisher verification (needs repo result)
    const pubResult = await verifyPublisher(entry.name, repoResult);
    result.publisher = pubResult;
    result.identity.publisher_verified = pubResult.verified;
    if (pubResult.error) result.errors.push(`publisher: ${pubResult.error}`);
  } else {
    // No repo URL — try publisher verification from name alone
    const pubResult = await verifyPublisher(entry.name);
    result.publisher = pubResult;
    result.identity.publisher_verified = pubResult.verified;
    if (pubResult.error) result.errors.push(`publisher: ${pubResult.error}`);
  }

  // 2. npm package existence
  if (entry.npmSpec) {
    const pkgResult = await verifyNpmPackage(entry.npmSpec);
    result.package = pkgResult;
    result.identity.package_verified = pkgResult.exists;
    if (pkgResult.error) result.errors.push(`package: ${pkgResult.error}`);
  }

  return result;
}

/**
 * Batch verify existence for multiple registry entries.
 * Respects GitHub API rate limits by adding delays between requests.
 * @param {Array} entries - registry entries
 * @param {object} opts - { onProgress, githubDelayMs, npmDelayMs }
 * @returns {Promise<Array>} Layer 1 results
 */
export async function batchVerifyExistence(entries, opts = {}) {
  const { onProgress, githubDelayMs = 200, npmDelayMs = 100 } = opts;
  const results = [];

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const result = await verifyExistence(entry);
    results.push(result);

    if (onProgress) onProgress(i + 1, entries.length, result);

    // Rate limit: GitHub is the bottleneck (60/hr unauthenticated)
    if (entry.repoUrl) await sleep(githubDelayMs);
    if (entry.npmSpec) await sleep(npmDelayMs);
  }

  return results;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
