import ky from 'ky'
import sanity from '@/lib/sanity.js'

export async function addMovie (hydrate, movie) {
  const res = await ky.post('/.netlify/functions/add', {
    json: movie
  }).json()

  await getSelections(hydrate)
}

export async function setWatched (hydrate, id) {
  const res = await ky.post('/.netlify/functions/setWatched', {
    json: { id }
  }).json()

  await getSelections(hydrate)
  await getMovies(hydrate)
}

export async function getSelections (hydrate) {
  const selections = await sanity.fetch(
    `*[_type == 'movie' && !defined(dateWatched)]{
      _id,
      user->{
        name
      },
      title,
      director,
      runtime,
      trailer
    }`
  )

  hydrate({ selections })()
}

export async function getMovies (hydrate) {
  const movies = await sanity.fetch(
    `*[_type == 'movie' && defined(dateWatched)]{
      user->{
        name
      },
      title,
      dateWatched
    }`
  )

  hydrate({ movies })()
}

export async function login (user) {
  return ky.post('/.netlify/functions/login', {
    json: user
  }).json()
}
