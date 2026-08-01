// The AIcap release version shown in user-facing install instructions.
//
// Single source for the frontend. The canonical value lives in the
// repo-root VERSION file; a Go test (TestVersionReferencesAreConsistent
// in main_test.go) fails the build if this constant, action.yml, the
// README, the CI templates, or the published guides drift from it.
//
// That test exists because they did drift: two releases shipped while
// the dashboard and two published guides carried on pointing readers at
// a much older tag. A version string duplicated across six surfaces and
// bumped by hand will eventually disagree with itself, and the surfaces
// users actually read are the ones nobody remembers to check.
export const AICAP_VERSION = 'v1.7.2';
