import {startupBudget} from './startup-budget.mjs';
// Limits, not sleeps: healthy startup/close returns immediately. A certificate
// helper may take 15 s; do not falsely report cleanup failure at the old 5 s cap.
export const managedBudgets=config=>({readyMs:Math.max(startupBudget(config),60000),stopMs:45000,requestTimeout:45000});
