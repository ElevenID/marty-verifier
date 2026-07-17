/**
 * Deployment Profile Management Component
 * 
 * Provides CRUD operations for deployment profiles with lane management
 */

import React, { useState, useEffect } from 'react';

interface DeploymentProfile {
  id: string;
  name: string;
  site_id?: string;
  network_mode: 'online' | 'offline' | 'hybrid';
  ux_config: {
    language: string;
    theme: string;
    show_operator_mode: boolean;
    accessibility_enabled: boolean;
    signage_text?: Record<string, string>;
  };
  update_policy: {
    auto_update: boolean;
    update_channel: string;
    rollout_percentage: number;
    rollout_ring?: string;
  };
  offline_cache_ttl_hours: number;
  operator_biometric_authentication_required: boolean;
}

interface Lane {
  id: string;
  name: string;
  deployment_profile_id: string;
  default_policy_id?: string;
  device_ids: string[];
  metadata?: Record<string, any>;
}

export const DeploymentProfileManager: React.FC = () => {
  const [profiles, setProfiles] = useState<DeploymentProfile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<DeploymentProfile | null>(null);
  const [lanes, setLanes] = useState<Lane[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchProfiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/v1/identity/deployment-profiles');
      if (!response.ok) throw new Error('Failed to fetch profiles');
      const data = await response.json();
      setProfiles(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  // Fetch profiles on mount
  useEffect(() => {
    fetchProfiles();
  }, []);

  const fetchLanes = async (profileId: string) => {
    try {
      const response = await fetch(`/api/v1/identity/deployment-profiles/${profileId}/lanes`);
      if (!response.ok) throw new Error('Failed to fetch lanes');
      const data = await response.json();
      setLanes(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    }
  };

  const selectProfile = (profile: DeploymentProfile) => {
    setSelectedProfile(profile);
    fetchLanes(profile.id);
  };

  return (
    <div className="deployment-profile-manager">
      <h1>Deployment Profile Management</h1>

      {error && <div className="error-banner">{error}</div>}

      <div className="layout">
        {/* Profile List */}
        <div className="profile-list">
          <div className="header">
            <h2>Profiles</h2>
            <button onClick={fetchProfiles} disabled={loading}>
              Refresh
            </button>
          </div>

          {loading ? (
            <div>Loading...</div>
          ) : (
            <ul>
              {profiles.map((profile) => (
                <li
                  key={profile.id}
                  className={selectedProfile?.id === profile.id ? 'selected' : ''}
                  onClick={() => selectProfile(profile)}
                >
                  <div className="profile-item">
                    <strong>{profile.name}</strong>
                    <span className="badge">{profile.network_mode}</span>
                    {profile.site_id && <span className="site-id">Site: {profile.site_id}</span>}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Profile Details */}
        {selectedProfile && (
          <div className="profile-details">
            <h2>{selectedProfile.name}</h2>

            <section className="config-section">
              <h3>Network Configuration</h3>
              <dl>
                <dt>Mode:</dt>
                <dd>{selectedProfile.network_mode}</dd>
                <dt>Offline Cache TTL:</dt>
                <dd>{selectedProfile.offline_cache_ttl_hours}h</dd>
              </dl>
            </section>

            <section className="config-section">
              <h3>UX Configuration</h3>
              <dl>
                <dt>Language:</dt>
                <dd>{selectedProfile.ux_config.language}</dd>
                <dt>Theme:</dt>
                <dd>{selectedProfile.ux_config.theme}</dd>
                <dt>Accessibility:</dt>
                <dd>{selectedProfile.ux_config.accessibility_enabled ? 'Enabled' : 'Disabled'}</dd>
                {selectedProfile.ux_config.signage_text && (
                  <>
                    <dt>Signage Text:</dt>
                    <dd>
                      <ul>
                        {Object.entries(selectedProfile.ux_config.signage_text).map(([lang, text]) => (
                          <li key={lang}>
                            <strong>{lang}:</strong> {text}
                          </li>
                        ))}
                      </ul>
                    </dd>
                  </>
                )}
              </dl>
            </section>

            <section className="config-section">
              <h3>Update Policy</h3>
              <dl>
                <dt>Auto Update:</dt>
                <dd>{selectedProfile.update_policy.auto_update ? 'Enabled' : 'Disabled'}</dd>
                <dt>Channel:</dt>
                <dd>{selectedProfile.update_policy.update_channel}</dd>
                <dt>Rollout:</dt>
                <dd>{selectedProfile.update_policy.rollout_percentage}%</dd>
                {selectedProfile.update_policy.rollout_ring && (
                  <>
                    <dt>Ring:</dt>
                    <dd>{selectedProfile.update_policy.rollout_ring}</dd>
                  </>
                )}
              </dl>
            </section>

            {/* Lanes Section */}
            <section className="lanes-section">
              <h3>Lanes ({lanes.length})</h3>
              <ul className="lanes-list">
                {lanes.map((lane) => (
                  <li key={lane.id} className="lane-item">
                    <strong>{lane.name}</strong>
                    <span className="device-count">{lane.device_ids.length} devices</span>
                    {lane.default_policy_id && (
                      <span className="policy-override">Policy Override</span>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          </div>
        )}
      </div>
    </div>
  );
};

export default DeploymentProfileManager;
