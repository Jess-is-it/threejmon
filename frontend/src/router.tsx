import { createBrowserRouter } from "react-router-dom";
import { AppShell } from "./ui/AppShell";
import { DashboardPage } from "./views/DashboardPage";
import { UsagePage } from "./views/UsagePage";
import { OfflinePage } from "./views/OfflinePage";
import { PlaceholderPage } from "./views/PlaceholderPage";
import { SurveillancePage } from "./views/SurveillancePage";
import { OpticalPage } from "./views/OpticalPage";
import { PulsewatchPage } from "./views/PulsewatchPage";
import { WanPage } from "./views/WanPage";
import { AccountsPingPage } from "./views/AccountsPingPage";

export const router = createBrowserRouter([
  {
    path: "/app",
    element: <AppShell />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "usage", element: <UsagePage /> },
      { path: "offline", element: <OfflinePage /> },
      { path: "surveillance", element: <SurveillancePage /> },
      { path: "profile-review", element: <PlaceholderPage title="Profile Review" legacyHref="/profile-review" /> },
      { path: "optical", element: <OpticalPage /> },
      { path: "accounts-ping", element: <AccountsPingPage /> },
      { path: "wan", element: <WanPage /> },
      { path: "pulsewatch", element: <PulsewatchPage /> },
      { path: "system", element: <PlaceholderPage title="System Settings" legacyHref="/settings/system" /> }
    ],
  },
]);
