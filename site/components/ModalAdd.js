import React, { useState } from 'react'
import { connect } from '@picostate/react'
import { addMovie } from '@/lib/actions.js'
import { formValues } from '@/lib/utils.js'

export default connect(state => {
  return {
    isOpen: state.modalAdd
  }
}, {
  addMovie,
  close (hydrate) {
    hydrate({ modalAdd: false })()
  },
})(({ isOpen, close, addMovie }) => {
  const [ loading, setLoading ] = useState(false)

  return isOpen ? (
    <div className='modal fix fill z10'>
      <button
        className='modal__close abs top right'
        onClick={close}
      >+</button>

      <div className='outer'>
        <div className='container--s'>
          <form onSubmit={async e => {
            e.preventDefault()
            setLoading(true)
            const movie = formValues(e.target)
            await addMovie(movie)
            setLoading(false)
            close()
          }}>
            <input
              type='text'
              name='title'
              placeholder='Title'
            />
            <input
              type='text'
              name='director'
              placeholder='Director'
            />
            <input
              type='text'
              name='runtime'
              placeholder='Runtime in minutes i.e. 120'
            />
            <input
              type='text'
              name='trailer'
              placeholder='Trailer URL (YouTube)'
            />

            <button className='button' type='submit' disabled={loading}>
              {loading ? 'Adding' : 'Add'}
            </button>
          </form>
        </div>
      </div>
    </div>
  ) : null
})
