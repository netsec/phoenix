function outputJson(inp) {
    $('#output').html(JSON.stringify(inp, null, 2));
}

function buildQuery(queryBuilderId) {
    let rules = $('#' + queryBuilderId).queryBuilder('getESBool');
       post("/advanced_search/", {
            "query": JSON.stringify(rules),
            "lastRules": JSON.stringify( $('#' + queryBuilderId).queryBuilder('getRules'))
        });
    // let invisible = $('div#queryBuilderToo').length ? $('div#queryBuilderToo') : $('<div id="queryBuilderToo" display="none">');
    // let subFilters = [];
    // let seen = new Set();
    // $.getJSON("/static/fields.json", function (data) {
    //     data.forEach(group => {
    //         group.fields.forEach(field => {
    //             if (!seen.has(field)) {
    //                 subFilters.push({'id': field, 'type': group.type || "string"});
    //                 seen.add(field);
    //             }
    //         })
    //     });
    //     invisible.queryBuilder({
    //         filters: subFilters
    //     });
    //     let newRule = recurseRules(rules,data);
    //     invisible.queryBuilder('setRules', newRule);
    //     post("/advanced_search/", {
    //         "query": JSON.stringify(invisible.queryBuilder('getESBool')),
    //         "lastRules": JSON.stringify(rules)
    //     });
    //
    // });
}

function recurseRules(group,data) {
    let newParent = {"condition": group.condition};
    newParent.rules = [];
    group.rules.forEach(subRule => {
        if (subRule.rules) {
//                Group
            newParent.rules.push(recurseRules(subRule,data));
        }
        else {
//                Rule
            let newRule = {"condition": "OR"};
            let dirField = data.find(x => x.name === subRule.field);
            let subFields = dirField.fields;
            newRule["rules"] = [];
            for (let fieldIndex in subFields) {
                let fieldName = subFields[fieldIndex];
                newRule.rules.push({
                    id: fieldName,
                    field: fieldName,
                    type: subRule.type,
                    input: subRule.input,
                    operator: subRule.operator,
                    value: subRule.value
                });
            }
            newParent.rules.push(newRule);
        }
    });
    return newParent;
}

// Post to the provided URL with the specified parameters.
function post(path, parameters) {
    var form = $('#subForm');

    form.attr("method", "post");
    form.attr("action", path);

    $.each(parameters, function (key, value) {
        var field = $('<input></input>');

        field.attr("type", "hidden");
        field.attr("name", key);
        field.attr("value", value);

        form.append(field);
    });

    // The form needs to be a part of the document in
    // order for us to be able to submit it.
    form.submit();
}