# Changelog

## 0.1.0 (2026-11-04)


### Features

* add per-node host firewall controller ([91877bb](https://github.com/baprx/host-firewall-controller/commit/91877bb14b0f6e5caa172bb64d16f71bf2c11ef4))


### Bug Fixes

* **controller:** harden rule updates and convergence safety ([dca89c3](https://github.com/baprx/host-firewall-controller/commit/dca89c37411eb2d1bfddca58d7bd1e51e8d359f5))
* **e2e:** remove a race in the rule-repair e2e test ([47ce05d](https://github.com/baprx/host-firewall-controller/commit/47ce05d80e0c1a633e10e76b485ee5f227b373d1))
* **ufw:** serialize ufw calls with ufw's own rule-file lock ([3a4dead](https://github.com/baprx/host-firewall-controller/commit/3a4dead5cdd9df451d9c71d3ffcd893c379b3276))
