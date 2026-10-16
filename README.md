# TellurPakPatch (Tellurium + LargePakPatch)

A combined solution featuring a universal SSL bypass/redirect alongside a corrupted data fix for native Unreal Engine HTTP games (specifically designed for Fortnite).

---

## 📌 Overview

- **Tellurium:** Universal redirect and SSL bypass for Unreal Engine games.
- **LargePakPatch:** Universal corrupted data fix for Fortnite.

---

## 🚀 Getting Started & Setup

### Configuring Tellurium

To configure Tellurium, edit the settings in `TellurPakPatch/Options.h`:

- **Change Backend URL:** Modify the `Backend` variable to point to your URL.
- **Mode Settings (`UrlSet`):**
  - Set to `Hybrid` to build for a Hybrid server.
  - Set to `Dev` to build for a Dev server.
  - Set to `All` to redirect all traffic.
- **Debugging Console:** Set `Console` to `true` to enable the debug console.

### How to Use
To use it, simply configure the target server URL you wish to redirect to, then compile and build the `.dll`.

- **Supported Builds:** Tested and confirmed working on versions **v28.30** and **v12.41**

---

## 📜 Credits & Acknowledgments

- **Tellurium:** [Ploosh](https://github.com/plooshi) ([Original Repository](https://github.com/plooshi/Tellurium))
- **LargePakPatch:** [Twin1](https://github.com/Twin1dev) & [parkie](https://github.com/mlodyskiny) ([Original Repository](https://github.com/Twin1dev/LargePakPatch/))
- **Modified by:** [Crisutf](https://github.com/Crisutf)