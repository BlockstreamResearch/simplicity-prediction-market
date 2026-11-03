export async function fetchAdmin(url: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(url, { ...init, redirect: 'manual' })
  if (response.type !== 'opaqueredirect') return response

  const currentPage = new URL(window.location.href)
  if (new URL(url, currentPage).origin !== currentPage.origin) {
    throw new Error('Admin single sign-on requires the same-origin API proxy. Leave VITE_SERVER_API unset.')
  }
  const signIn = new URL('/oauth2/start', currentPage)
  signIn.searchParams.set('rd', currentPage.href)
  window.location.assign(signIn.href)
  throw new Error('Redirecting to single sign-on. Retry the admin action after signing in.')
}
