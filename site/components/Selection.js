import React from 'react'
import { connect } from '@picostate/react'
import { setWatched } from '@/lib/actions.js'

export default connect(state => {
  return {
    isLoggedIn: state.isLoggedIn
  }
}, {
  setWatched
})(({
  _id,
  user,
  title,
  director,
  runtime,
  trailer,
  isLoggedIn,
  setWatched
}) => {
  return (
    <div className='selection mb1'>
      <h3 className='__title'>
        {title}

        {isLoggedIn && (
          <button
            className='selection__watched'
            onClick={e => setWatched(_id)}
          >+</button>
        )}
      </h3>
      <div className='selection__sub f aic fw'>
        <p className='h6'><strong>Time:</strong> {runtime} mins</p>
        <p className='h6'><strong>Director:</strong> {director}</p>
        <p className='h6'><strong><a href={trailer} target='_blank'>Watch the Trailer</a></strong></p>
      </div>

    </div>
  )
})
