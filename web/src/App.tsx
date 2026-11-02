import { useQuery } from "@tanstack/react-query";
import { Route, Switch } from "wouter";
import { api, ApiError, ok } from "./api/client";
import { Shell } from "./components/Shell";
import { Approvals } from "./pages/Approvals";
import { Home } from "./pages/Home";
import { InstancePage } from "./pages/Instance";
import { Keys } from "./pages/Keys";
import { Login, Setup } from "./pages/Auth";
import { Modules } from "./pages/Modules";
import { PolicyPage } from "./pages/Policy";
import { Settings } from "./pages/Settings";
import { Timeline } from "./pages/Timeline";

export default function App() {
  const setup = useQuery({ queryKey: ["setup"], queryFn: () => ok(api.GET("/setup")) });
  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => ok(api.GET("/me")),
    enabled: setup.data?.needsSetup === false,
    retry: false,
  });

  if (setup.isPending) return null;
  if (setup.error) {
    return (
      <div className="gate">
        <div className="gate-box stack">
          <h1>Conduit isn't reachable</h1>
          <p className="muted">The daemon didn't answer. Check that conduitd is running, then reload.</p>
        </div>
      </div>
    );
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
        <Route path="/i/:id">{(p) => <InstancePage id={p.id} />}</Route>
        <Route path="/policy" component={PolicyPage} />
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
