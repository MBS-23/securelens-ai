import Editor, { type OnMount } from "@monaco-editor/react";
import { useEffect, useRef } from "react";
import { monacoLanguage } from "../lib/format";
import { monaco } from "../lib/monaco";
import { usePrefs } from "../lib/prefs";
import type { FileMarker } from "../lib/types";
import { Spinner } from "./ui";

type Editor = Parameters<OnMount>[0];

/**
 * Read-only source view. Content is displayed as text in a Monaco model —
 * never interpreted as HTML — and secrets have already been masked by the API.
 */
export function CodeViewer({
  path,
  language,
  content,
  markers,
  focusLine,
  onMarkerClick,
  height = "70vh",
}: {
  path: string;
  language: string | null;
  content: string;
  markers: FileMarker[];
  focusLine?: number | null;
  onMarkerClick?: (marker: FileMarker) => void;
  height?: string;
}) {
  const { theme } = usePrefs();
  const editorRef = useRef<Editor | null>(null);
  const decorations = useRef<string[]>([]);

  const apply = () => {
    const editor = editorRef.current;
    if (!editor) return;
    decorations.current = editor.deltaDecorations(
      decorations.current,
      markers
        .filter((m) => m.line)
        .map((m) => ({
          range: new monaco.Range(m.line!, 1, m.end_line && m.end_line >= m.line! ? m.end_line : m.line!, 1),
          options: {
            isWholeLine: true,
            className: `sl-line sl-line-${m.severity}`,
            glyphMarginClassName: `sl-glyph sl-glyph-${m.severity}`,
            glyphMarginHoverMessage: { value: `**${m.public_id}** ${m.severity} — ${m.title.replace(/[*_`[\]]/g, "")}` },
            overviewRuler: { color: m.severity === "CRITICAL" || m.severity === "HIGH" ? "#ff5d5d" : "#f2c14e", position: monaco.editor.OverviewRulerLane.Right },
          },
        })),
    );
  };

  useEffect(apply, [markers, content]);
  useEffect(() => {
    if (focusLine && editorRef.current) {
      editorRef.current.revealLineInCenter(focusLine);
      editorRef.current.setPosition({ lineNumber: focusLine, column: 1 });
    }
  }, [focusLine, content]);

  const onMount: OnMount = (editor) => {
    editorRef.current = editor;
    apply();
    if (focusLine) editor.revealLineInCenter(focusLine);
    editor.onMouseDown((event) => {
      if (event.target.type !== monaco.editor.MouseTargetType.GUTTER_GLYPH_MARGIN || !onMarkerClick) return;
      const line = event.target.position?.lineNumber;
      const marker = markers.find((m) => m.line === line);
      if (marker) onMarkerClick(marker);
    });
  };

  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <Editor
        height={height}
        path={path}
        language={monacoLanguage(language, path)}
        value={content}
        theme={theme === "dark" ? "securelens-dark" : "securelens-light"}
        onMount={onMount}
        loading={<Spinner />}
        options={{
          readOnly: true,
          domReadOnly: true,
          minimap: { enabled: true },
          glyphMargin: true,
          fontSize: 13,
          scrollBeyondLastLine: false,
          renderLineHighlight: "line",
          wordWrap: "off",
          automaticLayout: true,
          links: false,
          contextmenu: false,
        }}
      />
    </div>
  );
}
