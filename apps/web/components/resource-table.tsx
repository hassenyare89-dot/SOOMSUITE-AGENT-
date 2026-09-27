"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Empty, ErrorNote } from "@/components/page";
import { type Page, useApi } from "@/lib/api";

export type Column<T> = { key: string; header: string; render: (row: T) => React.ReactNode };

/** Generic paginated list backed by a gateway endpoint returning Page<T> (or T[]). */
export function ResourceTable<T extends Record<string, unknown>>({
  path, columns, pageSize = 25, rowKey, empty = "Nothing here yet.", reloadSignal = 0,
}: {
  path: string; columns: Column<T>[]; pageSize?: number; rowKey: (row: T) => string;
  empty?: string; reloadSignal?: number;
}) {
  const [offset, setOffset] = React.useState(0);
  const sep = path.includes("?") ? "&" : "?";
  const { data, error, loading, reload } = useApi<Page<T> | T[]>(
    `${path}${sep}limit=${pageSize}&offset=${offset}`, [reloadSignal]);
  const items = Array.isArray(data) ? data : data?.items ?? [];
  const total = Array.isArray(data) ? data.length : data?.total ?? 0;
  React.useEffect(() => setOffset(0), [path]);
  return (
    <div>
      <ErrorNote error={error} />
      <Table>
        <THead>
          <tr>{columns.map((c) => <TH key={c.key}>{c.header}</TH>)}</tr>
        </THead>
        <TBody>
          {items.map((row) => (
            <TR key={rowKey(row)}>{columns.map((c) => <TD key={c.key}>{c.render(row)}</TD>)}</TR>
          ))}
        </TBody>
      </Table>
      {!loading && items.length === 0 ? <Empty>{empty}</Empty> : null}
      <div className="mt-3 flex items-center justify-between text-xs text-muted">
        <span>{loading ? "Loading…" : `${total} total`}</span>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => void reload()}>Refresh</Button>
          <Button size="sm" variant="outline" disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - pageSize))}>Previous</Button>
          <Button size="sm" variant="outline" disabled={offset + pageSize >= total}
                  onClick={() => setOffset(offset + pageSize)}>Next</Button>
        </div>
      </div>
    </div>
  );
}
