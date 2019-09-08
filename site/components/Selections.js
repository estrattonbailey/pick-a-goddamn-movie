import React from 'react'
import { connect } from '@picostate/react'
import Selection from '@/components/Selection.js'

export default connect(state => {
  return {
    selections: state.selections
  }
})(({ selections }) => (
  <div className='outer'>
    <div className='container'>
      <div className='selections rel f fw'>
        <div className='selections__left is-eric rel'>
          <h5 className='selections__title inline-block bg-eric caps cw'>Eric's Movies</h5>
          {
            selections
              .filter(selection => selection.user.name === 'Eric')
              .map(selection => <Selection key={selection.title} {...selection} />)
          }
        </div>
        <div className='selections__right is-mel rel'>
          <h5 className='selections__title inline-block bg-mel caps cw'>Melanie's Movies</h5>
          {
            selections
              .filter(selection => selection.user.name === 'Melanie')
              .map(selection => <Selection key={selection.title} {...selection} />)
          }
        </div>
      </div>
    </div>
  </div>
))
