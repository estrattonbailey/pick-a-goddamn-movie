export function formValues (form) {
  let values = {}

  for (let field of form.elements) {
    if (field.value) values[field.name] = field.value
  }

  return values
}
