import React from 'react'
import { connect } from '@picostate/react'

const months = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec'
]

export default connect(state => {
  return {
    movies: state.movies
  }
})(({ movies }) => (
  <div className='movies outer'>
    <div className='container'>
      <div className='movies__inner rel f fw jcb'>
        <div className='movies__left is-eric rel'>
          <h1>The latest titles retired from the lineup:</h1>
        </div>
        <div className='movies__right is-mel rel x'>
          {
            movies
              .reverse()
              .map(movie => {
                const cx = movie.user.name === 'Eric' ? 'is-eric' : 'is-mel'
                const date = new Date(movie.dateWatched)
                const month = months[date.getMonth()]
                const day = date.getDay() + 1
                const year = date.getFullYear()
                return (
                  <div
                    key={movie.title}
                    className={`movie f aic jcb cw x ${cx}`}
                  >
                    <h3>{movie.title}</h3>
                    <h6>{month} {day}, {year}</h6>
                  </div>
                )
              })
          }
        </div>
      </div>
    </div>
  </div>
))
