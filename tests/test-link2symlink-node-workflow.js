'use strict';

const fs = require('fs');
const path = require('path');

function expect(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function expectRegular(stat, nlink, label) {
  expect(stat.isFile(), `${label}: expected a regular file`);
  expect(stat.nlink === nlink,
    `${label}: expected nlink=${nlink}, got ${stat.nlink}`);
}

const project = '/project';
const packageDir = path.join(project, 'node_modules', 'pkg');
const source = path.join(packageDir, 'source.js');
const modulePath = path.join(packageDir, 'index.js');
const app = path.join(project, 'app.js');

fs.mkdirSync(packageDir, { recursive: true });
for (let index = 0; index < 64; index++) {
  fs.writeFileSync(path.join(packageDir, `type-${index}.d.ts`),
    `export type T${index} = number;\n`);
}
fs.writeFileSync(source, 'module.exports = 41;\n');
fs.linkSync(source, modulePath);
fs.writeFileSync(app,
  "module.exports = { value: require('pkg'), resolved: require.resolve('pkg') };\n");

expectRegular(fs.lstatSync(source), 2, 'source before module load');
expectRegular(fs.lstatSync(modulePath), 2, 'module before module load');

const loaded = require(app);
expect(loaded.value === 41, `expected module value 41, got ${loaded.value}`);
expect(loaded.resolved === modulePath,
  `module resolution leaked ${loaded.resolved} instead of ${modulePath}`);

expectRegular(fs.lstatSync(source), 1, 'source after module load');
expectRegular(fs.lstatSync(modulePath), 1, 'module after module load');

try {
  fs.readlinkSync(modulePath);
  throw new Error('materialized module remained a symlink');
} catch (error) {
  if (error.code !== 'EINVAL') {
    throw error;
  }
}

const fd = fs.openSync(modulePath, 'r');
try {
  expectRegular(fs.fstatSync(fd), 1, 'materialized module fd');
} finally {
  fs.closeSync(fd);
}

let typeCount = 0;
for (const entry of fs.readdirSync(packageDir, { withFileTypes: true })) {
  if (entry.name.endsWith('.d.ts')) {
    expectRegular(fs.statSync(path.join(packageDir, entry.name)), 1, entry.name);
    typeCount++;
  }
}
expect(typeCount === 64, `expected 64 type files, got ${typeCount}`);

console.log('link2symlink node module workflow passed');
