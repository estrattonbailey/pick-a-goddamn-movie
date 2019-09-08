import '@/styles/main.css'

import React from 'react'
import { render } from 'react-dom'
import createStore from 'picostate'
import { Picostate, connect } from '@picostate/react'

import App from '@/components/App.js'
import Selections from '@/components/Selections.js'
import Movies from '@/components/Movies.js'
import Copy from '@/components/Copy.js'
import Footer from '@/components/Footer.js'
import GIF from '@/components/GIF.js'
import ModalAdd from '@/components/ModalAdd.js'
import ModalLogin from '@/components/ModalLogin.js'

const store = createStore({
  modalLogin: false,
  modalAdd: false,
  selections: [],
  movies: [],
  gif: false,
})

window.store = store

render((
  <Picostate store={store}>
    <App>
      <Selections />
      <Movies />
      <Copy />
      <Footer />
      <ModalAdd />
      <ModalLogin />
      <GIF />
    </App>
  </Picostate>
), document.getElementById('root'))
