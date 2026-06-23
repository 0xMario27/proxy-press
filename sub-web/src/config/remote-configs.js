// 远程配置选项
const ACL4SSR_REMOTE = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config";
const ACL4SSR_LOCAL = "Clash/config";  // Docker 挂载的本地路径，瞬间加载
const SLEEPY_BASE = "https://cdn.jsdelivr.net/gh/SleepyHeeead/subconverter-config@master/remote-config";

export const REMOTE_CONFIGS = [
  {
    label: "⚡ 本地规则（极速）",
    options: [
      { label: "Online Full 全分组", value: `${ACL4SSR_LOCAL}/ACL4SSR_Online_Full.ini` },
      { label: "Online 默认版", value: `${ACL4SSR_LOCAL}/ACL4SSR_Online.ini` },
      { label: "Online Mini", value: `${ACL4SSR_LOCAL}/ACL4SSR_Online_Mini.ini` },
    ]
  },
  {
    label: "ACL4SSR Online (远程)",
    options: [
      { label: "Online 默认版", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online.ini` },
      { label: "Online AdblockPlus", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_AdblockPlus.ini` },
      { label: "Online Full 全分组", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Full.ini` },
      { label: "Online Full AdblockPlus", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Full_AdblockPlus.ini` },
      { label: "Online Full Google", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Full_Google.ini` },
      { label: "Online Full MultiMode", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Full_MultiMode.ini` },
      { label: "Online Full Netflix", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Full_Netflix.ini` },
      { label: "Online Full NoAuto", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Full_NoAuto.ini` },
      { label: "Online Mini", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Mini.ini` },
      { label: "Online Mini AdblockPlus", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Mini_AdblockPlus.ini` },
      { label: "Online Mini Fallback", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Mini_Fallback.ini` },
      { label: "Online Mini MultiCountry", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Mini_MultiCountry.ini` },
      { label: "Online Mini MultiMode", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Mini_MultiMode.ini` },
      { label: "Online Mini NoAuto", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_Mini_NoAuto.ini` },
      { label: "Online MultiCountry", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_MultiCountry.ini` },
      { label: "Online NoAuto", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_NoAuto.ini` },
      { label: "Online NoReject", value: `${ACL4SSR_REMOTE}/ACL4SSR_Online_NoReject.ini` }
    ]
  },
  {
    label: "ACL4SSR 本地/直连",
    options: [
      { label: "ACL4SSR 默认", value: `${ACL4SSR_REMOTE}/ACL4SSR.ini` },
      { label: "ACL4SSR BackCN", value: `${ACL4SSR_REMOTE}/ACL4SSR_BackCN.ini` },
      { label: "ACL4SSR Mini", value: `${ACL4SSR_REMOTE}/ACL4SSR_Mini.ini` },
      { label: "ACL4SSR Mini Fallback", value: `${ACL4SSR_REMOTE}/ACL4SSR_Mini_Fallback.ini` },
      { label: "ACL4SSR Mini NoAuto", value: `${ACL4SSR_REMOTE}/ACL4SSR_Mini_NoAuto.ini` },
      { label: "ACL4SSR NoApple", value: `${ACL4SSR_REMOTE}/ACL4SSR_NoApple.ini` },
      { label: "ACL4SSR NoAuto", value: `${ACL4SSR_REMOTE}/ACL4SSR_NoAuto.ini` },
      { label: "ACL4SSR NoAuto NoApple", value: `${ACL4SSR_REMOTE}/ACL4SSR_NoAuto_NoApple.ini` },
      { label: "ACL4SSR NoMicrosoft", value: `${ACL4SSR_REMOTE}/ACL4SSR_NoMicrosoft.ini` },
      { label: "ACL4SSR WithGFW", value: `${ACL4SSR_REMOTE}/ACL4SSR_WithGFW.ini` }
    ]
  },
  {
    label: "universal",
    options: [
      { label: "No-Urltest", value: `${SLEEPY_BASE}/universal/no-urltest.ini` },
      { label: "Urltest", value: `${SLEEPY_BASE}/universal/urltest.ini` }
    ]
  },
  {
    label: "customized",
    options: [
      { label: "Maying", value: `${SLEEPY_BASE}/customized/maying.ini` },
      { label: "Ytoo", value: `${SLEEPY_BASE}/customized/ytoo.ini` },
      { label: "FlowerCloud", value: `${SLEEPY_BASE}/customized/flowercloud.ini` },
      { label: "Nexitally", value: `${SLEEPY_BASE}/customized/nexitally.ini` },
      { label: "SoCloud", value: `${SLEEPY_BASE}/customized/socloud.ini` },
      { label: "ARK", value: `${SLEEPY_BASE}/customized/ark.ini` },
      { label: "ssrCloud", value: `${SLEEPY_BASE}/customized/ssrcloud.ini` }
    ]
  },
  {
    label: "Special",
    options: [
      { label: "NeteaseUnblock(仅规则，No-Urltest)", value: `${SLEEPY_BASE}/special/netease.ini` },
      { label: "Basic(仅GEOIP CN + Final)", value: `${SLEEPY_BASE}/special/basic.ini` }
    ]
  }
];
