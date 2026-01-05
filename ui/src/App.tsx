import { HashRouter, Routes, Route } from 'react-router-dom';
import { Box } from '@mui/material';
import Layout from '@components/Layout';
import VerificationPage from '@/pages/VerificationPage';
import SettingsPage from '@/pages/SettingsPage';
import LicensePage from '@/pages/LicensePage';
import SyncPage from '@/pages/SyncPage';

function App() {
  return (
    <HashRouter>
      <Box sx={{ display: 'flex', minHeight: '100vh' }}>
        <Layout>
          <Routes>
            <Route path="/" element={<VerificationPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/license" element={<LicensePage />} />
            <Route path="/sync" element={<SyncPage />} />
          </Routes>
        </Layout>
      </Box>
    </HashRouter>
  );
}

export default App;
