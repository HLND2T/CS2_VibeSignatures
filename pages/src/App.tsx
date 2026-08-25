import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntApp, ConfigProvider, theme } from 'antd'
import enUS from 'antd/locale/en_US'
import zhCN from 'antd/locale/zh_CN'
import zhTW from 'antd/locale/zh_TW'
import { BrowserRouter } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ApiProvider } from './app/ApiProvider'
import { AppShell } from './app/AppShell'
import { resolveLanguage } from './i18n'
import { useTheme } from './theme/themeContext'
import './App.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 1000, refetchOnWindowFocus: false },
  },
})

const ANT_DESIGN_LOCALES = { en: enUS, 'zh-CN': zhCN, 'zh-TW': zhTW }

export default function App() {
  const { i18n } = useTranslation()
  const { theme: colorTheme } = useTheme()
  const isDark = colorTheme === 'dark'
  return (
    <ConfigProvider
      locale={ANT_DESIGN_LOCALES[resolveLanguage(i18n.resolvedLanguage)]}
      theme={{
        algorithm: isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          colorPrimary: '#3b82f6',
          borderRadius: 8,
          colorBgBase: isDark ? '#080d18' : '#e5eaf1',
          ...(!isDark && {
            colorBgLayout: '#e5eaf1',
            colorBgContainer: '#edf1f5',
            colorBgElevated: '#f1f4f7',
            colorFillAlter: 'rgba(100, 116, 139, 0.08)',
          }),
        },
      }}
    >
      <AntApp>
        <QueryClientProvider client={queryClient}>
          <ApiProvider>
            <BrowserRouter basename={import.meta.env.BASE_URL}>
              <AppShell />
            </BrowserRouter>
          </ApiProvider>
        </QueryClientProvider>
      </AntApp>
    </ConfigProvider>
  )
}
