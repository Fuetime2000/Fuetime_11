function initializeDataTable(tableId, translations) {
    $(tableId).DataTable({
        order: [[0, "desc"]],
        language: translations
    });
}
