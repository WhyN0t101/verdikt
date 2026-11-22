import type { IocHistory } from "../model";

/** The panel only appears when there is something to say: earlier reports, a case or a watch. */
export const hasStory = (d: IocHistory): boolean => d.reports.length > 1 || d.cases.length > 0 || d.watched;

export function changesText(n: number): string {
  return n === 0 ? "" : `${n} verdict change${n === 1 ? "" : "s"}`;
}
