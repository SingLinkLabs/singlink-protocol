# SingLink Beta 協議

**[English →](README.md)**

## 重點摘要

- **內容：** SingLink Beta 協議初代版本，SingLinkVPN 開源的代理／VPN 協議，以 Go 標準庫編寫。
- **授權：** Apache-2.0。「SingLink」、「SingLinkVPN」、星連／星连名稱與標誌為 SingLinkVPN 商標（見 [NOTICE](NOTICE)）。
- **署名：** 任何使用或轉發，都必須保留署名：軟件由原作者 SingLinkVPN 提供（見[署名](#署名)）。
- **版本：** 1.0.0-draft（規格第 4 版草案）。**發布日期：** 2026-11-12，星連VPN開源計畫第二階段。
- **安全：** 已完成內部安全審計，共 31 個問題，「高」和「中」等級全部修好或緩解（[docs/SECURITY-AUDIT.zh-Hant.md](docs/SECURITY-AUDIT.zh-Hant.md)）；之後完成兩次第三方原始碼審計（2026-11-13，以及 VPN Labs 的 [VPNL-2026-0013](https://vpn.com.de/reports/VPNL-2026-0013)），修正與立場見 [docs/SECURITY-REMEDIATION.md](docs/SECURITY-REMEDIATION.md)（英文）。
- **沿革：** SingLink Beta 協議從星連VPN 早期版本、SingLink Beta 一路演進到現在的 SingLink 2.0；初代版本延續了星連VPN 的帳號權限、裝置綁定與安全設計理念。
- **暫不公開：** 最新版本（SingLink 2.0 核心與現行星連VPN 正式 App），基於安全考量。
- **相關連結：** 初代客戶端 [singlink-vpn-app](https://github.com/SingLinkLabs/singlink-vpn-app) · 開源總庫 [singlink-vpn-open-source](https://github.com/SingLinkLabs/singlink-vpn-open-source) · [官網開源頁面](https://singlinkvpn.com/hk/tech/open-source/)

## 背景

SingLink Beta 協議從星連VPN 早期版本、SingLink Beta 一路演進到現在的 SingLink 2.0。這次開源的「SingLink Beta 協議初代版本」與「星連VPN 初代客戶端」，延續了星連VPN 一貫的帳號權限、裝置綁定與安全設計理念，並在通過安全審計後公開。正式版 App 與協議已升級到新一代架構，因安全考量暫不完全公開；我們只公開不構成安全風險的程式碼，開源計畫將持續進行。

## 概覽

SingLink Beta 協議是 SingLinkVPN 開源的初代 SingLink Beta 協議，是一套代理／VPN 協議。

它保留了 VLESS、Trojan 速度快的優點：TLS 連線一開始只送一次請求，第一段資料跟請求一起送出，不必多等一個來回。在這個基礎上，它補齊了正式營運 VPN 服務需要的能力。

## 跟 VLESS 比多了什麼

| | VLESS | SingLink Beta 協議 |
|---|---|---|
| 誰能連線 | 拿到共用 UUID 就能連 | 必須持有帳號後台簽發的**權限憑證**，加上綁定的裝置金鑰 |
| 節點上的用戶權限 | 協議本身沒有（要靠面板） | 到期時間、TCP／UDP 權限、限速、同時連線數，每個節點離線即可驗證並執行，節點上不放用戶資料庫 |
| 封鎖用戶 | 要逐台節點刪 UUID | 可按憑證、帳號或裝置封鎖，已連線的會話也會自動斷開 |
| 憑證外洩 | UUID 外洩就能被盜用 | 憑證綁定裝置金鑰，從節點偷走憑證也用不了 |
| 傳輸加密 | 只靠外層 TLS，經過 CDN 時 CDN 看得到明文 | 另有一層端到端加密，經過 CDN 也看不到內容 |
| 抗量子 | 沒有 | X25519 + ML-KEM-768（NIST 標準）混合金鑰交換 |
| 防探測 | 要另外設定回落 | 內建：沒通過驗證的連線一律轉給真實網站，不同探測方式的回應時間沒有差別 |
| 防重放 | 沒有 | 時間窗口、金鑰快取，節點重啟後同樣有效 |
| 節點防護 | 沒有 | 連線數上限、每個 IP 的上限、限制握手耗用的 CPU、完整內網封鎖、PROXY 協議、自動換金鑰 |

## 狀態

**版本：1.0.0-draft（規格第 4 版草案）**

- 只用 Go 標準庫的成熟加密元件，沒有第三方套件，也沒有自創加密演算法。
- 已完成**內部安全審計**，共找到 31 個問題，「高」和「中」等級全部修好或緩解，詳見 [docs/SECURITY-AUDIT.zh-Hant.md](docs/SECURITY-AUDIT.zh-Hant.md)。
- 每個修正都有對應的回歸測試，所有解析器都做過模糊測試。
- 已完成兩次**第三方原始碼審計**（2026-11-13，以及 VPN Labs 報告 [VPNL-2026-0013](https://vpn.com.de/reports/VPNL-2026-0013)），發現、修正與保留的設計取捨記錄在 [docs/SECURITY-REMEDIATION.md](docs/SECURITY-REMEDIATION.md)（英文）。審計不等於安全保證，協議也仍是草案；用於高風險場景前請先審慎評估。

## 目錄

| 路徑 | 內容 |
|---|---|
| `SPEC.md` | 協議規格（英文，對外開源用） |
| `singlink/` | 協議核心（Go） |
| `socks5/` | 本機 SOCKS5 入口（含 UDP，可選密碼） |
| `engine/` | 命令列和 App 共用的客戶端執行層 |
| `cmd/singlink/` | 命令列工具：產生金鑰、簽發憑證、產生連結、跑節點、跑客戶端、一鍵本機示範 |
| `ffi/` | 給 App 用的 C 介面 `libsinglink` |
| `deploy/` | 節點設定範例，以及強化過的 systemd 服務檔 |
| `docs/` | 安全審計報告與第三方審計修正紀錄 |

VPN App（Flutter）放在另一個獨立倉庫。

## 上線建議

1. **帳號後台：** 保管簽發金鑰，用戶付費或續費時簽發短效憑證（預設 1 天，由 App 自動續）。簽發前，要求裝置先用自己的金鑰簽名證明身份。
2. **App：** 在裝置上自己產生裝置金鑰，只把公鑰送給後台換憑證。私鑰不離開裝置。
3. **節點：**
   - 只需要節點私鑰和後台的簽發公鑰。節點不存用戶資料，也不記錄用戶去了哪些網站。
   - 每台節點用自己的金鑰，並定期輪替（`old_private_keys` 可讓新舊金鑰並存一段時間）。
4. **偽裝網站：** 節點網域放一個真實網站，`fallback` 指向它，並開啟 `fallback_proxy_protocol`，憑證用正式 CA 簽發。
5. **系統服務：** 用 `deploy/singlink.service` 部署，已包含系統沙盒、私鑰保護和崩潰自動重啟。

## 署名

任何使用或轉發，都必須保留署名：軟件由原作者 SingLinkVPN 提供。SingLink Beta 協議最初由 SingLinkVPN（https://singlinkvpn.com）開發並提供。轉發版本與衍生作品必須在自己的 NOTICE 檔，以及顯示第三方授權聲明或「關於」畫面的地方，重現 [NOTICE](NOTICE) 裡的署名文字，並且不得刪除原始檔開頭的版權標示，或命令列工具與程式庫輸出的 `Attribution` 署名常數（Apache License 2.0 第 4 條）。

## 授權與署名

採用 Apache License 2.0（見 [LICENSE](LICENSE) 與 [NOTICE](NOTICE)）。任何人轉發本專案或以它為基礎修改，都必須保留每個原始檔開頭的版權標示和 NOTICE 裡的署名「Based on the SingLink Beta Protocol by SingLinkVPN」與原作者 SingLinkVPN 的署名，並標明改過哪些檔案。「SingLink」「SingLinkVPN」「星連」「星连」名稱與圖示是 SingLinkVPN 的商標，修改版必須使用自己的名稱。

## 必要的安全狀態遷移

為防止重放攻擊，節點會短暫保存經加密處理的一次性握手標記，約 4 分鐘後自動刪除；標記不含 IP、網站、帳號或任何可識別用戶的資訊，不屬於日誌。

服務端要求這份防重放狀態事先明確初始化並持久保存，沒有記憶體回退模式。舊節點設定需新增
`replay_file`，並在新 key 首次啟動前用 `singlink replay-init` 初始化一次；key 仍被接受時不得清空或還原舊副本。
不同主機若接受同一把 key，必須共用同一個外部原子 store（或每台主機用自己的 key）。
同主機共享、跨主機外接 store、Windows 服務端 backend、clock/GC 行為及撤銷列表
明確 `empty` 格式，詳見[修復與部署契約](docs/SECURITY-REMEDIATION.md)。

## 規格版本升級

規格第 4 版草案更換了握手識別字串 `IDENT`，所有握手金鑰都和第 3 版不同，但封包格式與版本位元組（`0x01`）沒有改變。協議刻意不做版本協商，也不會退回明文或舊版本，因此節點、App 與原生程式庫必須一起升級：

| 節點 \ 客戶端（或原生程式庫） | 第 3 版客戶端 | 第 4 版客戶端 |
|---|---|---|
| **第 3 版節點** | 正常 | 節點：照常轉給偽裝網站；客戶端顯示「handshake rejected: possible protocol draft mismatch or wrong server key」 |
| **第 4 版節點** | 節點：照常轉給偽裝網站；第 3 版客戶端顯示舊的一般拒絕訊息 | 正常 |

金鑰、權杖、連結與防重放狀態不受影響。`singlink version` 與 FFI `SingLinkVersion` 會回報規格版本。詳見 [SPEC.md §10](SPEC.md#10-versioning-and-upgrade-compatibility)。
