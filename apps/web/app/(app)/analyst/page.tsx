"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

import { ErrorBox, PageHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  tool_calls: { tool: string }[];
  citations: { tool: string; summary: string }[];
  engine: string | null;
  created_at: string;
}
interface Conversation {
  id: string;
  title: string;
  updated_at: string;
}
interface Detail extends Conversation {
  messages: Message[];
}
interface Suggestions {
  enabled: boolean;
  engine: string;
  suggestions: string[];
}
interface AskResponse {
  conversation_id: string;
  message: Message;
}

export default function AnalystPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [cid, setCid] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  const suggestions = useQuery({
    queryKey: ["analyst-suggestions"],
    queryFn: () => api<Suggestions>("/v1/analyst/suggestions"),
    enabled: can("analyst.query"),
  });
  const conversations = useQuery({
    queryKey: ["analyst-conversations"],
    queryFn: () => api<Conversation[]>("/v1/analyst/conversations"),
    enabled: can("analyst.query"),
  });
  const detail = useQuery({
    queryKey: ["analyst-conversation", cid],
    queryFn: () => api<Detail>(`/v1/analyst/conversations/${cid}`),
    enabled: !!cid,
  });

  const ask = useMutation({
    mutationFn: (question: string) =>
      api<AskResponse>("/v1/analyst/ask", {
        method: "POST",
        body: { question, conversation_id: cid },
      }),
    onSuccess: (r) => {
      setCid(r.conversation_id);
      setDraft("");
      qc.invalidateQueries({ queryKey: ["analyst-conversation", r.conversation_id] });
      qc.invalidateQueries({ queryKey: ["analyst-conversations"] });
    },
  });

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [detail.data?.messages.length, ask.isPending]);

  if (!can("analyst.query")) {
    return (
      <>
        <PageHeader title="Security Analyst" subtitle="AI Security Analyst (PRD §35)" />
        <p className="text-sm text-muted">You need the analyst.query permission.</p>
      </>
    );
  }

  const messages = cid ? (detail.data?.messages ?? []) : [];
  const pendingQuestion = ask.isPending ? ask.variables : null;

  function submit(q: string) {
    const question = q.trim();
    if (question && !ask.isPending) ask.mutate(question);
  }

  return (
    <>
      <PageHeader
        title="Security Analyst"
        subtitle="Ask about your agents, findings, incidents, and audit trail — read-only (PRD §35)"
        actions={
          <button className="btn" onClick={() => setCid(null)}>
            New conversation
          </button>
        }
      />

      <div className="flex gap-4">
        <div className="hidden w-56 shrink-0 flex-col gap-1 lg:flex">
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">
            History
          </div>
          {(conversations.data ?? []).length === 0 && (
            <p className="text-xs text-muted">No conversations yet.</p>
          )}
          {(conversations.data ?? []).map((c) => (
            <button
              key={c.id}
              onClick={() => setCid(c.id)}
              className={`truncate rounded-lg px-2 py-1.5 text-left text-xs ${
                c.id === cid ? "bg-accent/20 text-fg" : "text-muted hover:bg-panel"
              }`}
              title={c.title}
            >
              {c.title}
            </button>
          ))}
        </div>

        <div className="flex min-h-[60vh] flex-1 flex-col">
          <div className="flex-1 space-y-4">
            {messages.length === 0 && !pendingQuestion && (
              <div className="card">
                <p className="mb-3 text-sm text-muted">
                  {suggestions.data?.engine === "claude"
                    ? "Powered by Claude with read-only access to your control plane."
                    : "Running the deterministic analyst (set ANTHROPIC_API_KEY for Claude)."}
                </p>
                <div className="flex flex-wrap gap-2">
                  {(suggestions.data?.suggestions ?? []).map((s) => (
                    <button
                      key={s}
                      onClick={() => submit(s)}
                      className="btn text-xs"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {detail.isLoading && cid && <Spinner />}
            {detail.error && <ErrorBox error={detail.error} />}

            {messages.map((m) => (
              <Bubble key={m.id} message={m} />
            ))}
            {pendingQuestion && (
              <>
                <Bubble
                  message={{
                    id: "pending-q",
                    role: "user",
                    content: pendingQuestion,
                    tool_calls: [],
                    citations: [],
                    engine: null,
                    created_at: "",
                  }}
                />
                <div className="text-sm text-muted">Analyst is thinking…</div>
              </>
            )}
            {ask.error && <ErrorBox error={ask.error} />}
            <div ref={endRef} />
          </div>

          <form
            className="mt-4 flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              submit(draft);
            }}
          >
            <input
              className="input flex-1"
              placeholder="Ask a security question…"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            <button className="btn btn-primary" disabled={ask.isPending || !draft.trim()}>
              Ask
            </button>
          </form>
        </div>
      </div>
    </>
  );
}

function Bubble({ message }: { message: Message }) {
  const mine = message.role === "user";
  return (
    <div className={`flex ${mine ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-2xl rounded-xl px-3 py-2 text-sm ${
          mine ? "bg-accent/20" : "border border-border bg-panel2"
        }`}
      >
        <div className="whitespace-pre-wrap">{message.content}</div>
        {message.tool_calls.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {message.tool_calls.map((t, i) => (
              <span key={i} className="rounded bg-panel px-1.5 py-0.5 font-mono text-[10px] text-muted">
                {t.tool}
              </span>
            ))}
          </div>
        )}
        {!mine && message.engine && (
          <div className="mt-1 text-[10px] text-muted">
            engine: {message.engine}
            {message.citations.length > 0 && ` · ${message.citations.length} sources`}
          </div>
        )}
      </div>
    </div>
  );
}
