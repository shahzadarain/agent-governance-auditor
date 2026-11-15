// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState, type ReactNode } from "react";

export type SortDir = "asc" | "desc";

export interface Column<T> {
  key: string;
  label: string;
  /** Value used for sorting. Leave out for a column that cannot be sorted. */
  sort?: (row: T) => string | number | null;
  render: (row: T) => ReactNode;
  align?: "right";
  /** Marks the cell that names the row (rendered as a row header). */
  rowHeader?: boolean;
}

function compare(a: string | number | null, b: string | number | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1; // unknown values go last in ascending order
  if (b === null) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), "en", { numeric: true, sensitivity: "base" });
}

export function sortRows<T>(rows: T[], col: Column<T> | undefined, dir: SortDir): T[] {
  if (!col?.sort) return rows;
  const get = col.sort;
  const out = [...rows].sort((x, y) => compare(get(x), get(y)));
  return dir === "desc" ? out.reverse() : out;
}

/** A table with sortable column headers. Sorting is announced with aria-sort. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  initialSort,
  empty,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  caption: string;
  initialSort?: { key: string; dir: SortDir };
  empty?: ReactNode;
}) {
  const [sort, setSort] = useState<{ key: string; dir: SortDir } | null>(initialSort ?? null);
  const sorted = useMemo(
    () =>
      sortRows(
        rows,
        columns.find((c) => c.key === sort?.key),
        sort?.dir ?? "asc",
      ),
    [rows, columns, sort],
  );

  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={caption}>
      <table className="table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => {
              const active = sort?.key === c.key;
              return (
                <th
                  key={c.key}
                  scope="col"
                  className={c.align === "right" ? "num" : undefined}
                  aria-sort={c.sort ? (active ? (sort.dir === "asc" ? "ascending" : "descending") : "none") : undefined}
                >
                  {c.sort ? (
                    <button
                      type="button"
                      className="th-sort"
                      onClick={() => setSort(active && sort.dir === "asc" ? { key: c.key, dir: "desc" } : { key: c.key, dir: "asc" })}
                    >
                      {c.label}
                      <span className={`sort-ind${active ? ` ${sort.dir}` : ""}`} aria-hidden="true" />
                    </button>
                  ) : (
                    c.label
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => (
            <tr key={rowKey(r)}>
              {columns.map((c) =>
                c.rowHeader ? (
                  <th key={c.key} scope="row">
                    {c.render(r)}
                  </th>
                ) : (
                  <td key={c.key} className={c.align === "right" ? "num" : undefined}>
                    {c.render(r)}
                  </td>
                ),
              )}
            </tr>
          ))}
          {sorted.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="table-empty">
                {empty ?? "Nothing to show."}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
