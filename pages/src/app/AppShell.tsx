import { DashboardOutlined, GlobalOutlined } from '@ant-design/icons'
import { Layout, Select, Space, Tabs, Typography } from 'antd'
import { lazy, Suspense, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { APP_LANGUAGES, changeLanguage, resolveLanguage, type AppLanguage } from '../i18n'
import { ThemeToggle } from '../theme/ThemeToggle'

const { Header, Content } = Layout
const ExploreSymbolsPage = lazy(() => import('../features/symbols/ExploreSymbolsPage').then((module) => ({ default: module.ExploreSymbolsPage })))
const ExploreGameDataPage = lazy(() => import('../features/gamedata/ExploreGameDataPage').then((module) => ({ default: module.ExploreGameDataPage })))

type AppTab = 'symbols' | 'gamedata'

export function AppShell() {
  const [activeTab, setActiveTab] = useState<AppTab>('symbols')
  const { t, i18n } = useTranslation()
  const selectedLanguage = resolveLanguage(i18n.resolvedLanguage)

  return (
    <Layout className="app-layout">
      <Header className="app-header">
        <a href="https://github.com/HLND2T/CS2_VibeSignatures" target="_blank" rel="noopener noreferrer" className="app-brand">
          <DashboardOutlined />
          <Typography.Text strong>CS2 VibeSignatures</Typography.Text>
        </a>
        <Tabs
          className="app-nav"
          activeKey={activeTab}
          onChange={(key) => setActiveTab(key === 'gamedata' ? 'gamedata' : 'symbols')}
          items={[
            { key: 'symbols', label: t('navigation.symbols') },
            { key: 'gamedata', label: t('navigation.gamedata') },
          ]}
        />
        <Space className="app-controls" align="center">
          <Select
            aria-label={t('language.selector')}
            value={selectedLanguage}
            onChange={(language: AppLanguage) => void changeLanguage(language)}
            options={APP_LANGUAGES.map((language) => ({
              value: language,
              label: <><GlobalOutlined /> {t(`language.${language === 'en' ? 'english' : language === 'zh-CN' ? 'simplifiedChinese' : 'traditionalChinese'}`)}</>,
            }))}
            style={{ width: 158 }}
          />
          <ThemeToggle />
        </Space>
      </Header>
      <Content className="app-content">
        <Suspense fallback={<div className="page-spinner">{t('app.loadingPage')}</div>}>
          {activeTab === 'symbols' ? <ExploreSymbolsPage /> : <ExploreGameDataPage />}
        </Suspense>
      </Content>
    </Layout>
  )
}
