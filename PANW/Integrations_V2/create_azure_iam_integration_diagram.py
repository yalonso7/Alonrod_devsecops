#!/usr/bin/env python3
"""
Create Azure IAM Integrations Architecture Diagram
Purpose: Generate a visual diagram of Azure IAM integrations with Cortex XDR, XSOAR, and Prisma Cloud
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import os

# Set figure size and DPI for high quality
fig, ax = plt.subplots(1, 1, figsize=(16, 12))
ax.set_xlim(0, 10)
ax.set_ylim(0, 10)
ax.axis('off')

# Define colors
azure_color = '#0078D4'  # Microsoft Azure Blue
xdr_color = '#4A90E2'
xsoar_color = '#7B68EE'
prisma_color = '#00A8E8'
integration_color = '#95A5A6'
monitor_color = '#00BCF2'  # Azure Monitor Blue

# Title
ax.text(5, 9.5, 'Azure IAM Integrations Architecture', 
        ha='center', va='top', fontsize=20, fontweight='bold')

# Azure IAM Source Box
azure_box = FancyBboxPatch((0.5, 6), 2, 2.5, 
                          boxstyle="round,pad=0.1", 
                          facecolor=azure_color, edgecolor='black', linewidth=2)
ax.add_patch(azure_box)
ax.text(1.75, 7.75, 'Azure IAM', ha='center', va='center', 
        fontsize=14, fontweight='bold', color='white')

# Azure IAM Components
ax.text(1.75, 7.3, '• Users', ha='center', va='center', fontsize=10, color='white')
ax.text(1.75, 7.0, '• Service Principals', ha='center', va='center', fontsize=10, color='white')
ax.text(1.75, 6.7, '• Role Assignments', ha='center', va='center', fontsize=10, color='white')
ax.text(1.75, 6.4, '• RBAC Roles', ha='center', va='center', fontsize=10, color='white')
ax.text(1.75, 6.1, '• Azure AD', ha='center', va='center', fontsize=10, color='white')

# Azure Monitor Activity Logs Box
monitor_box = FancyBboxPatch((0.5, 3), 2, 1.5, 
                             boxstyle="round,pad=0.1", 
                             facecolor=monitor_color, edgecolor='black', linewidth=2)
ax.add_patch(monitor_box)
ax.text(1.75, 3.75, 'Azure Monitor', ha='center', va='center', 
        fontsize=12, fontweight='bold', color='white')
ax.text(1.75, 3.4, 'Activity Logs', ha='center', va='center', 
        fontsize=10, color='white')

# Integration Layer Box
integration_box = FancyBboxPatch((3.5, 4.5), 3, 3, 
                                 boxstyle="round,pad=0.1", 
                                 facecolor=integration_color, edgecolor='black', linewidth=2)
ax.add_patch(integration_box)
ax.text(5, 7, 'Integration Layer', ha='center', va='center', 
        fontsize=12, fontweight='bold', color='white')
ax.text(5, 6.5, '• Event Processing', ha='center', va='center', fontsize=9, color='white')
ax.text(5, 6.2, '• Incident Creation', ha='center', va='center', fontsize=9, color='white')
ax.text(5, 5.9, '• Alert Generation', ha='center', va='center', fontsize=9, color='white')
ax.text(5, 5.6, '• CIEM Sync', ha='center', va='center', fontsize=9, color='white')
ax.text(5, 5.3, '• Remediation', ha='center', va='center', fontsize=9, color='white')

# Cortex XDR Box
xdr_box = FancyBboxPatch((7.5, 6.5), 2, 2, 
                        boxstyle="round,pad=0.1", 
                        facecolor=xdr_color, edgecolor='black', linewidth=2)
ax.add_patch(xdr_box)
ax.text(8.5, 7.75, 'Cortex XDR', ha='center', va='center', 
        fontsize=12, fontweight='bold', color='white')
ax.text(8.5, 7.3, '• Incidents', ha='center', va='center', fontsize=9, color='white')
ax.text(8.5, 7.0, '• Threat Detection', ha='center', va='center', fontsize=9, color='white')
ax.text(8.5, 6.7, '• Automated Response', ha='center', va='center', fontsize=9, color='white')

# XSOAR Box
xsoar_box = FancyBboxPatch((7.5, 4), 2, 2, 
                          boxstyle="round,pad=0.1", 
                          facecolor=xsoar_color, edgecolor='black', linewidth=2)
ax.add_patch(xsoar_box)
ax.text(8.5, 5.25, 'Cortex XSOAR', ha='center', va='center', 
        fontsize=12, fontweight='bold', color='white')
ax.text(8.5, 4.8, '• Playbooks', ha='center', va='center', fontsize=9, color='white')
ax.text(8.5, 4.5, '• Investigations', ha='center', va='center', fontsize=9, color='white')
ax.text(8.5, 4.2, '• Automation', ha='center', va='center', fontsize=9, color='white')

# Prisma Cloud Box
prisma_box = FancyBboxPatch((7.5, 1.5), 2, 2, 
                           boxstyle="round,pad=0.1", 
                           facecolor=prisma_color, edgecolor='black', linewidth=2)
ax.add_patch(prisma_box)
ax.text(8.5, 2.75, 'Prisma Cloud', ha='center', va='center', 
        fontsize=12, fontweight='bold', color='white')
ax.text(8.5, 2.3, '• CIEM', ha='center', va='center', fontsize=9, color='white')
ax.text(8.5, 2.0, '• Least Privilege', ha='center', va='center', fontsize=9, color='white')
ax.text(8.5, 1.7, '• Compliance', ha='center', va='center', fontsize=9, color='white')

# Arrows from Azure IAM to Azure Monitor
arrow1 = FancyArrowPatch((1.75, 6), (1.75, 4.5), 
                         arrowstyle='->', mutation_scale=20, 
                         color='black', linewidth=2)
ax.add_patch(arrow1)
ax.text(2.3, 5.2, 'IAM Events', ha='left', va='center', fontsize=9, 
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

# Arrow from Azure IAM to Integration Layer
arrow2 = FancyArrowPatch((2.5, 7.25), (3.5, 6.5), 
                         arrowstyle='->', mutation_scale=20, 
                         color='black', linewidth=2)
ax.add_patch(arrow2)
ax.text(2.8, 6.8, 'User/SP Data', ha='left', va='center', fontsize=9,
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

# Arrow from Azure Monitor to Integration Layer
arrow3 = FancyArrowPatch((2.5, 3.75), (3.5, 5.5), 
                         arrowstyle='->', mutation_scale=20, 
                         color='black', linewidth=2)
ax.add_patch(arrow3)
ax.text(2.8, 4.6, 'Activity Logs', ha='left', va='center', fontsize=9,
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

# Arrow from Integration Layer to Cortex XDR
arrow4 = FancyArrowPatch((6.5, 7.25), (7.5, 7.5), 
                         arrowstyle='->', mutation_scale=20, 
                         color='black', linewidth=2)
ax.add_patch(arrow4)
ax.text(6.8, 7.4, 'Incidents', ha='left', va='center', fontsize=9,
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

# Arrow from Integration Layer to XSOAR
arrow5 = FancyArrowPatch((6.5, 6), (7.5, 5), 
                         arrowstyle='->', mutation_scale=20, 
                         color='black', linewidth=2)
ax.add_patch(arrow5)
ax.text(6.8, 5.5, 'Playbooks', ha='left', va='center', fontsize=9,
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

# Arrow from Integration Layer to Prisma Cloud
arrow6 = FancyArrowPatch((6.5, 4.5), (7.5, 2.5), 
                         arrowstyle='->', mutation_scale=20, 
                         color='black', linewidth=2)
ax.add_patch(arrow6)
ax.text(6.8, 3.5, 'CIEM Data', ha='left', va='center', fontsize=9,
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))

# Feedback arrows (dashed)
# From XDR to Integration
feedback1 = FancyArrowPatch((7.5, 7), (6.5, 6.5), 
                            arrowstyle='->', mutation_scale=15, 
                            color='gray', linewidth=1.5, linestyle='--', alpha=0.6)
ax.add_patch(feedback1)
ax.text(6.8, 6.7, 'Response', ha='right', va='center', fontsize=8, 
        color='gray', style='italic')

# From XSOAR to Integration
feedback2 = FancyArrowPatch((7.5, 4.5), (6.5, 5.5), 
                            arrowstyle='->', mutation_scale=15, 
                            color='gray', linewidth=1.5, linestyle='--', alpha=0.6)
ax.add_patch(feedback2)
ax.text(6.8, 5.0, 'Actions', ha='right', va='center', fontsize=8, 
        color='gray', style='italic')

# From Prisma Cloud to Integration
feedback3 = FancyArrowPatch((7.5, 2), (6.5, 5), 
                            arrowstyle='->', mutation_scale=15, 
                            color='gray', linewidth=1.5, linestyle='--', alpha=0.6)
ax.add_patch(feedback3)
ax.text(6.8, 3.5, 'Analysis', ha='right', va='center', fontsize=8, 
        color='gray', style='italic')

# Legend
legend_elements = [
    mpatches.Patch(facecolor=azure_color, label='Azure IAM'),
    mpatches.Patch(facecolor=monitor_color, label='Azure Monitor'),
    mpatches.Patch(facecolor=integration_color, label='Integration Layer'),
    mpatches.Patch(facecolor=xdr_color, label='Cortex XDR'),
    mpatches.Patch(facecolor=xsoar_color, label='Cortex XSOAR'),
    mpatches.Patch(facecolor=prisma_color, label='Prisma Cloud')
]
ax.legend(handles=legend_elements, loc='lower left', fontsize=10, framealpha=0.9)

# Add data flow labels at the bottom
ax.text(5, 0.5, 'Data Flow: Azure IAM → Integration Layer → Security Platforms', 
        ha='center', va='center', fontsize=10, style='italic')

# Save as JPEG
plt.tight_layout()
output_path = os.path.join(os.path.dirname(__file__), 'Azure_IAM_Integrations_Diagram.jpg')
plt.savefig(output_path, 
            format='jpeg', dpi=300, bbox_inches='tight', facecolor='white')
print(f"Diagram saved as {output_path}")

plt.close()
