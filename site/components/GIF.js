import React from 'react'
import { connect } from '@picostate/react'

export default connect(state => {
  return {
    active: state.gif
  }
})(({ active }) => {
  return active ? (
    <section className='gif fix fill z10'>
      <img src='/michael.gif' className='x y' />
    </section>
  ) : null
})
