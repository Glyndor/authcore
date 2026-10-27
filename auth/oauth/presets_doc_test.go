// Package presets holds the black-box tests and the captured provider
// documents (testdata/providers) that pin the presets published by
// auth/oauth (Google, Microsoft, GitHub, Discord, Apple, Vercel) against what
// each provider really serves. The presets themselves live in the parent
// package because they return its Provider type.
package oauth_test
