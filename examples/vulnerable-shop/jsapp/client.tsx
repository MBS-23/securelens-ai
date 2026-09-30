import React from "react";
import OpenAI from "openai";

export function Comment({ html }: { html: string }) {
  const q = new URLSearchParams(window.location.search).get("q");
  document.getElementById("out")!.innerHTML = q ?? "";
  return <div dangerouslySetInnerHTML={{ __html: location.hash }} />;
}

export async function answer(question: string) {
  const client = new OpenAI({ dangerouslyAllowBrowser: true });
  const completion = await client.chat.completions.create({ model: "x", messages: [{ role: "user", content: question }] });
  const text = completion.choices[0].message.content;
  document.body.innerHTML = text;
  eval(text);
}
