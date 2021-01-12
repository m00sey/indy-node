const core = require('@actions/core');

try {
  const common = core.getInput('common');
  console.log(`${common}`);

  const node = core.getInput('node');
  console.log(`${node}`);

  core.setOutput("matrix-common", common);
  core.setOutput("matrix-node", node);

} catch (error) {
  core.setFailed(error.message);
}