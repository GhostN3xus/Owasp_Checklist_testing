export function calculateProgress(itemStates) {
    const total = itemStates.length;
    const completed = itemStates.filter((item) => item.checked).length;
    const percent = total === 0 ? 0 : Math.round((completed / total) * 100);
    return { total, completed, percent };
}

export function renderStatusBadge(status) {
    if (status === "passed") {
      return '<span class="badge badge-passed">Passou</span>';
    }
    if (status === "failed") {
      return '<span class="badge badge-failed">Falhou</span>';
    }
    if (status === "na") {
      return '<span class="badge badge-na">N/A</span>';
    }
    return '<span class="badge badge-empty">--</span>';
}
