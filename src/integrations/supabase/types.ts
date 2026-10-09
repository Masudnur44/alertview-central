export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.18"
  }
  public: {
    Tables: {
      alerts: {
        Row: {
          acknowledged_at: string | null
          asset_id: string | null
          assignee: string | null
          description: string | null
          detected_at: string
          id: string
          incident_id: string | null
          mitre_tactic: string | null
          mitre_technique: string | null
          resolved_at: string | null
          severity: Database["public"]["Enums"]["severity"]
          source: string
          status: string
          title: string
        }
        Insert: {
          acknowledged_at?: string | null
          asset_id?: string | null
          assignee?: string | null
          description?: string | null
          detected_at?: string
          id?: string
          incident_id?: string | null
          mitre_tactic?: string | null
          mitre_technique?: string | null
          resolved_at?: string | null
          severity: Database["public"]["Enums"]["severity"]
          source: string
          status?: string
          title: string
        }
        Update: {
          acknowledged_at?: string | null
          asset_id?: string | null
          assignee?: string | null
          description?: string | null
          detected_at?: string
          id?: string
          incident_id?: string | null
          mitre_tactic?: string | null
          mitre_technique?: string | null
          resolved_at?: string | null
          severity?: Database["public"]["Enums"]["severity"]
          source?: string
          status?: string
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "alerts_asset_id_fkey"
            columns: ["asset_id"]
            isOneToOne: false
            referencedRelation: "assets"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "alerts_incident_fk"
            columns: ["incident_id"]
            isOneToOne: false
            referencedRelation: "incidents"
            referencedColumns: ["id"]
          },
        ]
      }
      assets: {
        Row: {
          address: string | null
          asset_type: string
          created_at: string
          criticality: Database["public"]["Enums"]["severity"]
          environment: string
          exposure: string
          id: string
          is_new: boolean
          last_seen: string
          monitored: boolean
          name: string
          owner: string | null
          status: string
          tls_expires_at: string | null
        }
        Insert: {
          address?: string | null
          asset_type: string
          created_at?: string
          criticality?: Database["public"]["Enums"]["severity"]
          environment?: string
          exposure?: string
          id?: string
          is_new?: boolean
          last_seen?: string
          monitored?: boolean
          name: string
          owner?: string | null
          status?: string
          tls_expires_at?: string | null
        }
        Update: {
          address?: string | null
          asset_type?: string
          created_at?: string
          criticality?: Database["public"]["Enums"]["severity"]
          environment?: string
          exposure?: string
          id?: string
          is_new?: boolean
          last_seen?: string
          monitored?: boolean
          name?: string
          owner?: string | null
          status?: string
          tls_expires_at?: string | null
        }
        Relationships: []
      }
      audit_log: {
        Row: {
          action: string
          actor: string | null
          created_at: string
          id: string
          target: string | null
        }
        Insert: {
          action: string
          actor?: string | null
          created_at?: string
          id?: string
          target?: string | null
        }
        Update: {
          action?: string
          actor?: string | null
          created_at?: string
          id?: string
          target?: string | null
        }
        Relationships: []
      }
      check_results: {
        Row: {
          asset_id: string | null
          check_type: string
          checked_at: string
          detail: string | null
          id: string
          ok: boolean
          response_ms: number | null
        }
        Insert: {
          asset_id?: string | null
          check_type: string
          checked_at?: string
          detail?: string | null
          id?: string
          ok: boolean
          response_ms?: number | null
        }
        Update: {
          asset_id?: string | null
          check_type?: string
          checked_at?: string
          detail?: string | null
          id?: string
          ok?: boolean
          response_ms?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "check_results_asset_id_fkey"
            columns: ["asset_id"]
            isOneToOne: false
            referencedRelation: "assets"
            referencedColumns: ["id"]
          },
        ]
      }
      detection_rules: {
        Row: {
          description: string | null
          enabled: boolean
          hits: number
          id: string
          mitre_technique: string | null
          name: string
          severity: Database["public"]["Enums"]["severity"]
        }
        Insert: {
          description?: string | null
          enabled?: boolean
          hits?: number
          id?: string
          mitre_technique?: string | null
          name: string
          severity: Database["public"]["Enums"]["severity"]
        }
        Update: {
          description?: string | null
          enabled?: boolean
          hits?: number
          id?: string
          mitre_technique?: string | null
          name?: string
          severity?: Database["public"]["Enums"]["severity"]
        }
        Relationships: []
      }
      event_sources: {
        Row: {
          api_key: string
          created_at: string
          id: string
          last_event_at: string | null
          name: string
          source_type: string
        }
        Insert: {
          api_key?: string
          created_at?: string
          id?: string
          last_event_at?: string | null
          name: string
          source_type: string
        }
        Update: {
          api_key?: string
          created_at?: string
          id?: string
          last_event_at?: string | null
          name?: string
          source_type?: string
        }
        Relationships: []
      }
      events: {
        Row: {
          event_type: string
          host: string | null
          id: string
          message: string | null
          occurred_at: string
          outcome: string | null
          raw: Json | null
          source_id: string | null
          src_ip: string | null
          username: string | null
        }
        Insert: {
          event_type: string
          host?: string | null
          id?: string
          message?: string | null
          occurred_at?: string
          outcome?: string | null
          raw?: Json | null
          source_id?: string | null
          src_ip?: string | null
          username?: string | null
        }
        Update: {
          event_type?: string
          host?: string | null
          id?: string
          message?: string | null
          occurred_at?: string
          outcome?: string | null
          raw?: Json | null
          source_id?: string | null
          src_ip?: string | null
          username?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "events_source_id_fkey"
            columns: ["source_id"]
            isOneToOne: false
            referencedRelation: "event_sources"
            referencedColumns: ["id"]
          },
        ]
      }
      incident_events: {
        Row: {
          author: string | null
          body: string
          created_at: string
          id: string
          incident_id: string
          kind: string
        }
        Insert: {
          author?: string | null
          body: string
          created_at?: string
          id?: string
          incident_id: string
          kind?: string
        }
        Update: {
          author?: string | null
          body?: string
          created_at?: string
          id?: string
          incident_id?: string
          kind?: string
        }
        Relationships: [
          {
            foreignKeyName: "incident_events_incident_id_fkey"
            columns: ["incident_id"]
            isOneToOne: false
            referencedRelation: "incidents"
            referencedColumns: ["id"]
          },
        ]
      }
      incidents: {
        Row: {
          closed_at: string | null
          contained_at: string | null
          id: string
          opened_at: string
          owner: string | null
          ref: string
          resolved_at: string | null
          severity: Database["public"]["Enums"]["severity"]
          status: string
          summary: string | null
          title: string
        }
        Insert: {
          closed_at?: string | null
          contained_at?: string | null
          id?: string
          opened_at?: string
          owner?: string | null
          ref?: string
          resolved_at?: string | null
          severity: Database["public"]["Enums"]["severity"]
          status?: string
          summary?: string | null
          title: string
        }
        Update: {
          closed_at?: string | null
          contained_at?: string | null
          id?: string
          opened_at?: string
          owner?: string | null
          ref?: string
          resolved_at?: string | null
          severity?: Database["public"]["Enums"]["severity"]
          status?: string
          summary?: string | null
          title?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string | null
          email: string | null
          id: string
        }
        Insert: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id: string
        }
        Update: {
          created_at?: string
          display_name?: string | null
          email?: string | null
          id?: string
        }
        Relationships: []
      }
      scheduler_token: {
        Row: {
          id: number
          token: string
        }
        Insert: {
          id?: number
          token?: string
        }
        Update: {
          id?: number
          token?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
      vulnerabilities: {
        Row: {
          asset_id: string | null
          cve: string | null
          cvss: number | null
          exploited_in_wild: boolean
          first_seen: string
          id: string
          internet_exposed: boolean
          last_seen: string
          severity: Database["public"]["Enums"]["severity"]
          status: string
          title: string
        }
        Insert: {
          asset_id?: string | null
          cve?: string | null
          cvss?: number | null
          exploited_in_wild?: boolean
          first_seen?: string
          id?: string
          internet_exposed?: boolean
          last_seen?: string
          severity: Database["public"]["Enums"]["severity"]
          status?: string
          title: string
        }
        Update: {
          asset_id?: string | null
          cve?: string | null
          cvss?: number | null
          exploited_in_wild?: boolean
          first_seen?: string
          id?: string
          internet_exposed?: boolean
          last_seen?: string
          severity?: Database["public"]["Enums"]["severity"]
          status?: string
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "vulnerabilities_asset_id_fkey"
            columns: ["asset_id"]
            isOneToOne: false
            referencedRelation: "assets"
            referencedColumns: ["id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      can_operate: { Args: { _user_id: string }; Returns: boolean }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      is_soc_member: { Args: { _user_id: string }; Returns: boolean }
    }
    Enums: {
      app_role:
        | "security_admin"
        | "security_analyst"
        | "security_manager"
        | "system_admin"
        | "management"
        | "auditor"
      severity: "critical" | "high" | "medium" | "low" | "info"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: [
        "security_admin",
        "security_analyst",
        "security_manager",
        "system_admin",
        "management",
        "auditor",
      ],
      severity: ["critical", "high", "medium", "low", "info"],
    },
  },
} as const
