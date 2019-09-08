import React, { useState } from 'react'
import cookie from 'js-cookie'
import { connect } from '@picostate/react'
import { login } from '@/lib/actions.js'
import { formValues } from '@/lib/utils.js'

export default connect(state => {
  return {
    isOpen: state.modalLogin
  }
}, {
  close (hydrate) {
    hydrate({ modalLogin: false })()
  },
  async login (hydrate, user) {
    const { token } = await login(user)
    cookie.set('pickagoddamnmovie', token, { expires: 365 })
    hydrate({
      modalLogin: false,
      isLoggedIn: true
    })()
  }
})(({ isOpen, close, login }) => {
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
            login(formValues(e.target))
            setLoading(false)
          }}>
            <input
              type='text'
              name='username'
              placeholder='Username'
            />
            <input
              type='password'
              name='password'
              placeholder='Password'
            />

            <button className='button' type='submit' disabled={loading}>
              {loading ? 'Logging In' : 'Log In'}
            </button>
          </form>
        </div>
      </div>
    </div>
  ) : null
})
