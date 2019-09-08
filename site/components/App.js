import React from 'react'
import { connect } from '@picostate/react'
import tighpo from 'tighpo'
import cookie from 'js-cookie'
import sscroll from 'sscroll'
import { getSelections, getMovies } from '@/lib/actions.js'

export default connect(state => state, {
  getSelections,
  getMovies,
  showLogin (hydrate) {
    hydrate({ modalLogin: true })()
  },
  showAdd (hydrate) {
    hydrate({ modalAdd: true })()
  }
})(
  class App extends React.Component {
    constructor (props) {
      super(props)

      this.state = {
        loading: true
      }
    }

    async componentDidMount () {
      const { getSelections, getMovies, showAdd, showLogin } = this.props

      await getSelections()
      await getMovies()

      this.setState({ loading: false })

      tighpo('login↩', () => {
        showLogin()
      })
      tighpo('add↩', () => {
        showAdd()
      })

      if (cookie.get('pickagoddamnmovie')) {
        this.props.hydrate({ isLoggedIn: true })()
      }
    }

    render () {
      const { loading } = this.state
      const { children } = this.props

      return loading ? (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh'
        }}>
          <img src='/favicon.png' style={{
            width: '50px',
            display: 'block'
          }} />
        </div>
      ) : (
        <div>
          <div className='outer'>
            <div className='f jce fw x'>
              <button 
                className='intro-button button'
                onClick={e => sscroll(document.getElementById('wtf'))}
              >WTF is this site?</button>
            </div>

            <div className='container x'>
              <div className='intro rel x'>
                <h1>Dinner may be up for debate, but it's time to pick a goddamn movie.</h1>
                <h4 className='open light mt1'><em>An innovative solution for an indecisive couple.</em></h4>
              </div>
            </div>
          </div>

          {children}
        </div>
      )
    }
  }
)
