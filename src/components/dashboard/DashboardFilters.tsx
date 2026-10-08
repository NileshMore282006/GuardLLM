import React from 'react';
import { DashboardFilterState, AuditEventItem } from '../../types/agentguard';
import { Filter, Search, RotateCcw } from 'lucide-react';

interface DashboardFiltersProps {
  filterState: DashboardFilterState;
  onFilterChange: (newFilter: DashboardFilterState) => void;
  loadedEvents: AuditEventItem[];
  totalLoaded: number;
  totalFiltered: number;
}

export const DashboardFilters: React.FC<DashboardFiltersProps> = ({
  filterState,
  onFilterChange,
  loadedEvents,
  totalLoaded,
  totalFiltered,
}) => {
  // Extract unique attack types dynamically from loaded events
  const uniqueAttackTypes = Array.from(
    new Set(
      loadedEvents
        .map((e) => e.attack_type)
        .filter((t): t is string => Boolean(t && t !== 'none'))
    )
  ).sort();

  // Extract unique actions dynamically from loaded events
  const uniqueActions = Array.from(
    new Set(
      loadedEvents
        .map((e) => e.action)
        .filter((a): a is string => Boolean(a))
    )
  ).sort();

  const handleDecisionChange = (decision: DashboardFilterState['decision']) => {
    onFilterChange({ ...filterState, decision });
  };

  const handleAttackChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({ ...filterState, attackType: e.target.value });
  };

  const handleActionChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({ ...filterState, actionCategory: e.target.value });
  };

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFilterChange({ ...filterState, searchQuery: e.target.value });
  };

  const handleReset = () => {
    onFilterChange({
      decision: 'ALL',
      attackType: 'ALL',
      actionCategory: 'ALL',
      searchQuery: '',
    });
  };

  const isFiltered =
    filterState.decision !== 'ALL' ||
    filterState.attackType !== 'ALL' ||
    filterState.actionCategory !== 'ALL' ||
    filterState.searchQuery.trim() !== '';

  return (
    <div className="glass-panel dashboard-filters-bar" style={{ padding: '0.875rem 1.25rem', marginBottom: '1rem' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}>
        
        {/* Left: Filter Controls */}
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.625rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            <Filter size={15} />
            <span style={{ fontWeight: 600 }}>Filter:</span>
          </div>

          {/* Decision Buttons */}
          <div className="filter-btn-group" style={{ display: 'flex', background: 'var(--bg-tertiary)', borderRadius: '6px', padding: '2px' }}>
            {(['ALL', 'ALLOW', 'BLOCK', 'ERROR'] as const).map((dec) => (
              <button
                key={dec}
                type="button"
                onClick={() => handleDecisionChange(dec)}
                style={{
                  background: filterState.decision === dec ? 'var(--color-accent)' : 'transparent',
                  color: filterState.decision === dec ? '#fff' : 'var(--text-secondary)',
                  border: 'none',
                  borderRadius: '4px',
                  padding: '0.25rem 0.6rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'background var(--transition-fast)',
                }}
              >
                {dec}
              </button>
            ))}
          </div>

          {/* Attack Type Dropdown */}
          <select
            value={filterState.attackType}
            onChange={handleAttackChange}
            aria-label="Filter by attack type"
            style={{
              background: 'var(--bg-tertiary)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '6px',
              padding: '0.25rem 0.6rem',
              fontSize: '0.75rem',
              cursor: 'pointer',
            }}
          >
            <option value="ALL">All Attack Types</option>
            {uniqueAttackTypes.map((atk) => (
              <option key={atk} value={atk}>
                {atk}
              </option>
            ))}
          </select>

          {/* Action / Resource Dropdown */}
          <select
            value={filterState.actionCategory}
            onChange={handleActionChange}
            aria-label="Filter by action category"
            style={{
              background: 'var(--bg-tertiary)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '6px',
              padding: '0.25rem 0.6rem',
              fontSize: '0.75rem',
              cursor: 'pointer',
            }}
          >
            <option value="ALL">All Actions</option>
            {uniqueActions.map((act) => (
              <option key={act} value={act}>
                {act}
              </option>
            ))}
          </select>

          {/* Search Box */}
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={13} style={{ position: 'absolute', left: '8px', color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search Request/Event ID..."
              value={filterState.searchQuery}
              onChange={handleSearchChange}
              aria-label="Search by Request or Event ID"
              style={{
                background: 'var(--bg-tertiary)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.25rem 0.6rem 0.25rem 1.6rem',
                fontSize: '0.75rem',
                width: '180px',
              }}
            />
          </div>

          {isFiltered && (
            <button
              type="button"
              onClick={handleReset}
              title="Reset all filters"
              style={{
                background: 'transparent',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-muted)',
                borderRadius: '6px',
                padding: '0.25rem 0.5rem',
                fontSize: '0.75rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.25rem',
                cursor: 'pointer',
              }}
            >
              <RotateCcw size={12} />
              Reset
            </button>
          )}
        </div>

        {/* Right: Dataset Labeling Notification */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '0.2rem 0.5rem', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
            Showing {totalFiltered} of {totalLoaded} loaded events (Client-Side Filter)
          </span>
        </div>

      </div>
    </div>
  );
};
