# Legacy web dashboard — superseded

This React/Vite dashboard has been **fully ported into the native Android app**
and is no longer built or deployed. It is kept here for reference only.

| Web page (`src/pages/`) | Native replacement (`app/src/main/java/com/cybershield/app/ui/`) |
|---|---|
| `Overview.jsx`        | `OverviewActivity.java` (admin — "Open analytics overview" button on Home) |
| `Queue.jsx`           | `QueueActivity.java` (bottom-nav "Queue") |
| `AnalyzeConsole.jsx`  | `AnalyzeConsoleActivity.java` (bottom-nav "Analyze") |
| `Reports.jsx`         | `ReportsActivity.java` (bottom-nav "Reports", admin only) |
| `Education.jsx`       | `EducationListActivity.java` + `EduDetailActivity.java` (bottom-nav "Learn") |
| `Login.jsx`           | `AuthActivity.java` |
| `Reset.jsx`           | `AuthActivity.java` via the `cybershield://reset` deep link |

Same backend endpoints are used: `/auth/*`, `/api/v1/analyze`, `/api/v1/history`,
`/api/v1/education/modules`, `/api/v1/stats`, `/api/v1/stats/trends`,
`/api/v1/admin/scans`, `/api/v1/admin/reports/*`.

To resurrect the web version: `npm install && npm run dev` in this folder
(nothing else in the repo depends on it).
