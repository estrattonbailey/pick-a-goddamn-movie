import { TiUserOutline } from 'react-icons/ti'

export default {
  icon: TiUserOutline,
  name: 'user',
  title: 'User',
  type: 'document',
  liveEdit: true,
  fields: [
    {
      name: 'name',
      title: 'Name',
      type: 'string'
    },
    {
      name: 'avatar',
      title: 'Avatar',
      type: 'image'
    }
  ],
}
