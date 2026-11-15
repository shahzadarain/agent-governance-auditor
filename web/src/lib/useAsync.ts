// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

export type AsyncState<T> =
  | { status: "loading"; data: null; error: null }
  | { status: "error"; data: null; error: ApiError }
  | { status: "ready"; data: T; error: null };

export type Async<T> = AsyncState<T> & {
  /** Runs the request again. With silent=true the current data stays visible. */
  reload: (silent?: boolean) => void;
  refreshing: boolean;
};

function toApiError(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  return new ApiError(0, "client_error", err instanceof Error ? err.message : "Something went wrong.");
}

/**
 * Runs an async loader when deps change. The loader gets an AbortSignal that
 * fires when the component unmounts or the deps change.
 */
export function useAsync<T>(loader: (signal: AbortSignal) => Promise<T>, deps: unknown[]): Async<T> {
  const [state, setState] = useState<AsyncState<T>>({ status: "loading", data: null, error: null });
  const [tick, setTick] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const silent = useRef(false);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => {
    const ctl = new AbortController();
    if (!silent.current) setState({ status: "loading", data: null, error: null });
    else setRefreshing(true);
    silent.current = false;
    loaderRef.current(ctl.signal).then(
      (data) => {
        if (ctl.signal.aborted) return;
        setRefreshing(false);
        setState({ status: "ready", data, error: null });
      },
      (err: unknown) => {
        if (ctl.signal.aborted) return;
        setRefreshing(false);
        setState({ status: "error", data: null, error: toApiError(err) });
      },
    );
    return () => ctl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback((quiet?: boolean) => {
    silent.current = quiet === true;
    setTick((n) => n + 1);
  }, []);

  return { ...state, reload, refreshing };
}
