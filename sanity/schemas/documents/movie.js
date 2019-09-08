import { FiFilm } from 'react-icons/fi'

export default {
  icon: FiFilm,
  name: 'movie',
  title: 'Movie',
  type: 'document',
  liveEdit: true,
  fields: [
    {
      name: 'user',
      title: 'User',
      type: 'reference',
      to: [ { type: 'user' } ]
    },
    {
      name: 'title',
      title: 'Title',
      type: 'string'
    },
    {
      name: 'director',
      title: 'Director',
      type: 'string'
    },
    {
      name: 'runtime',
      title: 'Runtime (in minutes)',
      type: 'number'
    },
    {
      name: 'trailer',
      title: 'Trailer',
      type: 'string'
    },
    {
      name: 'dateWatched',
      title: 'Date Watched',
      type: 'datetime'
    },
  ],
  preview: {
    select: {
      title: 'title',
      subtitle: 'dateWatched'
    },
    prepare (selection) {
      return {
        title: selection.title,
        subtitle: selection.subtitle ? 'Watched' : 'Selected'
      }
    }
  }
}
