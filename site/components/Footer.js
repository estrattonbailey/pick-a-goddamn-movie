import React from 'react'
import { connect } from '@picostate/react'

export default connect(state => ({}), {
  open (hydrate) {
    hydrate({ gif: true })()
  }
})(props => {
  return (
    <section className='footer outer'>
      <div className='container'>
        <h1>Want to suggest a movie?</h1>
        <h4 className='open light mt1'>
          <em>We'd love your recommendation. Just{' '}
            <a href='#' onClick={e => {
              e.preventDefault()
              props.open()
            }}>click here!</a>
          </em>
        </h4>
      </div>

      <div className='colophon py1'>
        <div className='outer py1'>
          <div className='container f jce h6'>
            &copy; 2019 • Lovingly made for Oscar & Miles
          </div>
        </div>
      </div>
    </section>
  )
})
