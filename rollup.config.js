import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'
import builtins from 'rollup-plugin-node-builtins'
import globals from 'rollup-plugin-node-globals'
import json from 'rollup-plugin-json'

export default {
  input: 'src/index.js',
  output: {
    file: 'dist/index.js',
    format: 'umd',
    name: "urbit-ob",
    exports: 'named'
  },
  plugins: [
    commonjs(),
    globals(),
    builtins(),
    resolve(),
    json()
  ]
}
