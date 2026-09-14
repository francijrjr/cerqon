import semver from "semver";

export const NODE_REQUIREMENT = ">=20.19.0";
export function isSupportedNodeVersion(version: string): boolean {
  return semver.valid(version) !== null && semver.satisfies(version, NODE_REQUIREMENT);
}
