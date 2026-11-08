# Changelog

## [0.4.1](https://github.com/baprx/host-firewall-controller/compare/v0.4.0...v0.4.1) (2026-11-08)


### Bug Fixes

* **controller:** tolerate shared rules and mid-reconcile deletion ([d86b585](https://github.com/baprx/host-firewall-controller/commit/d86b58539a629c42f7089eb441069aa7bbdbee8c))

## [0.4.0](https://github.com/baprx/host-firewall-controller/compare/v0.3.0...v0.4.0) (2026-11-06)


### Features

* **knock:** add dynamic IP knocks ([#39](https://github.com/baprx/host-firewall-controller/issues/39)) ([b2948b5](https://github.com/baprx/host-firewall-controller/commit/b2948b58d181df8c97925d24567ba75b3323e771))

## [0.3.0](https://github.com/baprx/host-firewall-controller/compare/v0.2.0...v0.3.0) (2026-11-05)


### Features

* **api:** make HostFirewallRule cluster-scoped ([4d2f556](https://github.com/baprx/host-firewall-controller/commit/4d2f556ed7d769fdc256835264dcb8629e98be10))

## [0.2.0](https://github.com/baprx/host-firewall-controller/compare/v0.1.1...v0.2.0) (2026-11-05)


### Features

* remove the allow-missing-ufw escape hatch ([3a48077](https://github.com/baprx/host-firewall-controller/commit/3a48077cbefcde5e77d83c3ead11d3d1f8cca3b3))

## [0.1.1](https://github.com/baprx/host-firewall-controller/compare/v0.1.0...v0.1.1) (2026-11-05)


### Bug Fixes

* **deps:** update kubernetes monorepo to v0.37.2 ([#13](https://github.com/baprx/host-firewall-controller/issues/13)) ([c0cb461](https://github.com/baprx/host-firewall-controller/commit/c0cb461817a4a8a81c8b7e63e3a697dd982976b2))
* **deps:** update module github.com/onsi/ginkgo/v2 to v2.34.0 ([#18](https://github.com/baprx/host-firewall-controller/issues/18)) ([278e74d](https://github.com/baprx/host-firewall-controller/commit/278e74d4d984be5e0173741f51ef144a4076db69))
* **deps:** update module github.com/onsi/gomega to v1.44.0 ([#19](https://github.com/baprx/host-firewall-controller/issues/19)) ([c698bad](https://github.com/baprx/host-firewall-controller/commit/c698badc69a77de2d7dde3dc2c44f11775222807))
* **deps:** update module github.com/prometheus/client_golang to v1.25.0 ([#25](https://github.com/baprx/host-firewall-controller/issues/25)) ([99d6098](https://github.com/baprx/host-firewall-controller/commit/99d6098db652834397c392b211ef2d516c137b12))
* **deps:** update module golang.org/x/sys to v0.49.0 ([#26](https://github.com/baprx/host-firewall-controller/issues/26)) ([8dabbb7](https://github.com/baprx/host-firewall-controller/commit/8dabbb784c866d5d691026d9acf6970e3689b674))
* **deps:** update module sigs.k8s.io/controller-runtime to v0.25.2 ([#14](https://github.com/baprx/host-firewall-controller/issues/14)) ([81413b4](https://github.com/baprx/host-firewall-controller/commit/81413b48bb649405f71eceefeab86181c49590ca))

## 0.1.0 (2026-11-04)


### Features

* add per-node host firewall controller ([91877bb](https://github.com/baprx/host-firewall-controller/commit/91877bb14b0f6e5caa172bb64d16f71bf2c11ef4))


### Bug Fixes

* **controller:** harden rule updates and convergence safety ([dca89c3](https://github.com/baprx/host-firewall-controller/commit/dca89c37411eb2d1bfddca58d7bd1e51e8d359f5))
* **e2e:** remove a race in the rule-repair e2e test ([47ce05d](https://github.com/baprx/host-firewall-controller/commit/47ce05d80e0c1a633e10e76b485ee5f227b373d1))
* **ufw:** serialize ufw calls with ufw's own rule-file lock ([3a4dead](https://github.com/baprx/host-firewall-controller/commit/3a4dead5cdd9df451d9c71d3ffcd893c379b3276))
