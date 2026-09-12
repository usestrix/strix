"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { rehypeCodeMeta, mdComponents } from "@/components/vulnerability/MdCodeBlock";

interface MarkdownProps {
  text: string;
  className?: string;
}

export default function Markdown({ text, className = "" }: MarkdownProps) {
  return (
    <div className={`prose-markdown ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeCodeMeta]}
        components={mdComponents}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
