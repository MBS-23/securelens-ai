import { Link, useLocation } from "react-router";
import { PageHeader } from "../components/ui";

export default function NotFound() {
  const location = useLocation();
  return (
    <>
      <PageHeader eyebrow="404" title="Page not found" />
      <p className="max-w-prose text-sm text-ink-2">
        Nothing exists at <code className="font-mono">{location.pathname}</code>. The link may be out of date, or the
        item may belong to a project you do not have access to.
      </p>
      <div className="mt-6 flex gap-3">
        <Link to="/" className="btn-primary">
          Go to the dashboard
        </Link>
        <Link to="/projects" className="btn-secondary">
          Browse projects
        </Link>
      </div>
    </>
  );
}
