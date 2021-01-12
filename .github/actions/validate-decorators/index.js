const core = require('@actions/core');

async function run() {
    // Output from `pytest_mark_check.py`
    // {
    //  "failed": boolean,
    //  "errors": array,
    //  "module": map
    // }
    let hasErrors = function bool(parsed) {
        return true
    };

    try {
        const common = core.getInput('common');
        const node = core.getInput('node');

        const commonJSON = JSON.parse(common)

        if (commonJSON.status == undefined) {
            core.setFailed('invalid input', common);
        }

    } catch (error) {
        core.setFailed(error.message);
    }
}
run();
