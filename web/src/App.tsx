import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Route, Switch } from "wouter";
import { api, ApiError, ok } from "./api/client";
import { Shell } from "./components/Shell";
import { Approvals } from "./pages/Approvals";
import { AssistantSettings } from "./pages/AssistantSettings";
import { Automations } from "./pages/Automations";
import { Home } from "./pages/Home";
import { InstancePage } from "./pages/Instance";
import { Keys } from "./pages/Keys";
import { Connect, Login, Setup } from "./pages/Auth";
import { forgetRelay, pairFromCode, relayProfile, routeLabel } from "./lib/connection";
import { onDeepLink } from "./lib/native";
import { useEffect } from "react";
import { Modules } from "./pages/Modules";
import { PolicyPage } from "./pages/Policy";
import { Settings } from "./pages/Settings";
import { Timeline } from "./pages/Timeline";

export default function App() {
  const qc = useQueryClient();
  // conduit://pair links opened from the phone's camera app pair directly.
  useEffect(
    () =>
      onDeepLink((url) => {
        if (url.startsWith("conduit://pair")) pairFromCode(url).then(() => qc.invalidateQueries(), () => {});
      }),
    [qc],
  );
  const setup = useQuery({ queryKey: ["setup"], queryFn: () => ok(api.GET("/setup")) });
  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => ok(api.GET("/me")),
    enabled: setup.data?.needsSetup === false,
    retry: false,
  });

  if (setup.isPending) return null;
  if (setup.error) {
    const relay = relayProfile();
    if (relay) {
      return (
        <div className="gate">
          <div className="gate-box stack">
            <h1>{relay.name} isn't reachable</h1>
            <p className="muted">
              {setup.error.message} Check that the computer is on and reachable {routeLabel(relay)}, then
              try again.
            </p>
            <div className="inline">
              <button className="btn primary" onClick={() => setup.refetch()}>
                Try again
              </button>
              <button
                className="btn"
                onClick={() => {
                  forgetRelay();
                  setup.refetch();
                }}
              >
                Forget this pairing
              </button>
            </div>
          </div>
        </div>
      );
    }
    return <Connect reason="No Conduit daemon answered here. If it runs on another computer, pair with it." />;
  }
  if (setup.data.needsSetup) return <Setup />;
  if (me.isPending) return null;
  if (me.error instanceof ApiError && me.error.status === 401) return <Login />;
  if (!me.data) return <Login />;

  return (
    <Shell me={me.data}>
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/approvals" component={Approvals} />
        <Route path="/timeline" component={Timeline} />
        <Route path="/modules" component={Modules} />
        <Route path="/automations" component={Automations} />
        <Route path="/i/:id">{(p) => <InstancePage id={p.id} />}</Route>
        <Route path="/policy" component={PolicyPage} />
        <Route path="/assistant" component={AssistantSettings} />
        <Route path="/keys" component={Keys} />
        <Route path="/settings" component={Settings} />
        <Route>
          <div className="page">
            <h1>Not found</h1>
            <p className="muted">There's nothing at this address.</p>
          </div>
        </Route>
      </Switch>
    </Shell>
  );
}
