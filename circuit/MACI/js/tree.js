const { poseidon } = require('circom')

class Tree {
  constructor(degree, depth, zero) {
    this.DEPTH = depth
    this.HEIGHT = depth + 1
    this.DEGREE = degree

    this.LEAVES_COUNT = degree ** depth
    this.LEAVES_IDX_0 = (degree ** depth - 1) / (degree - 1)
    this.NODES_COUNT = (degree ** (depth + 1) - 1) / (degree - 1)

    this.initZero(zero)
    this.initNodes()
  }

  get root() {
    return this.nodes[0]
  }

  initZero(zero) {
    const zeros = new Array(this.HEIGHT)
    zeros[0] = zero
    for (let i = 1; i < zeros.length; i++) {
      const children = new Array(this.DEGREE).fill(zeros[i - 1])
      zeros[i] = poseidon(children)
    }
    this.zeros = zeros
  }

  initNodes() {
    const DEGREE = this.DEGREE

    const nodes = new Array(this.NODES_COUNT)

    for (let d = this.DEPTH; d >= 0; d--) {
      const size = DEGREE ** d
      const idx0 = (DEGREE ** d - 1) / (DEGREE - 1)
      const zero = this.zeros[this.DEPTH - d]
      for (let i = 0; i < size; i++) {
        nodes[idx0 + i] = zero
      }
    }

    this.nodes = nodes
  }

  leaf(leafIdx) {
    if (leafIdx > this.LEAVES_COUNT || leafIdx < 0) {
      throw new Error('wrong leaf index')
    }
    const nodeIdx = this.LEAVES_IDX_0 + leafIdx
    return this.nodes[nodeIdx]
  }

  leaves() {
    return this.nodes.slice(this.LEAVES_IDX_0)
  }

  updateLeaf(leafIdx, leaf) {
    if (leafIdx > this.LEAVES_COUNT || leafIdx < 0) {
      throw new Error('wrong leaf index')
    }
    const nodeIdx = this.LEAVES_IDX_0 + leafIdx
    this.nodes[nodeIdx] = leaf

    this._update(nodeIdx)
  }

  pathIdxOf(leafIdx) {
    if (leafIdx > this.LEAVES_COUNT || leafIdx < 0) {
      throw new Error('wrong leaf index')
    }
    let idx = this.LEAVES_IDX_0 + leafIdx
    const pathIdx = []
    
    for (let i = 0; i < this.DEPTH; i++) {


      const parentIdx = Math.floor((idx - 1) / this.DEGREE)
      const childrenIdx0 = parentIdx * this.DEGREE + 1

      pathIdx.push(idx - childrenIdx0)

      idx = parentIdx
    }

    return pathIdx
  }

  pathElementOf(leafIdx) {
    if (leafIdx > this.LEAVES_COUNT || leafIdx < 0) {
      throw new Error('wrong leaf index')
    }
    let idx = this.LEAVES_IDX_0 + leafIdx
    const pathElement = []
    
    for (let h = 0; h < this.DEPTH; h++) {
      const parentIdx = Math.floor((idx - 1) / this.DEGREE)
      const childrenIdx0 = parentIdx * this.DEGREE + 1

      const el = []
      for (let i = childrenIdx0; i < childrenIdx0 + this.DEGREE; i++) {
        if (i === idx) continue
        el.push(this.nodes[i])
      }

      pathElement.push(el)

      idx = parentIdx
    }

    return pathElement
  }

  _update(nodeIdx) {
    let idx = nodeIdx
    while (idx > 0) {
      const parentIdx = Math.floor((idx - 1) / this.DEGREE)
      const childrenIdx0 = parentIdx * this.DEGREE + 1
      this.nodes[parentIdx] = poseidon(this.nodes.slice(childrenIdx0, childrenIdx0 + 5))

      idx = parentIdx
    }
  }
}

module.exports = Tree
